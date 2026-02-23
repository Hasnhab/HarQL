package burp;

import java.util.*;
import java.util.regex.*;

public class GraphQLHarvesterService {
    // Maximum size per module to prevent memory exhaustion and ReDoS attacks
    // 5MB is a good balance between coverage and safety (tested on Meta bundles)
    private static final int MAX_MODULE_SIZE = 5_000_000;
    private static final Pattern MODULE_PATTERN = Pattern.compile(
        "__d\\(\\s*\"([^\"]+)\"\\s*,\\s*function\\s*\\([^)]*\\)\\s*\\{\\s*(.*?)\\s*\\}\\s*,\\s*\\[.*?\\]\\s*\\)",
        Pattern.DOTALL
    );

    private static final Pattern DOC_ID_EXPORT = Pattern.compile(
        "(?:exports|module\\.exports)\\s*=\\s*\"?(\\d{15,20})\"?"
    );

    private static final Pattern GRAPHQL_TAG = Pattern.compile(
        "graphql\\s*`([\\s\\S]*?)`",
        Pattern.DOTALL
    );

    private static final Pattern RELAY_HOOK = Pattern.compile(
        "(useQuery|useLazyLoadQuery|useMutation|useSubscription|usePaginationFragment|useFragment|useRefetchableFragment)\\s*\\(\\s*[\"']([^\"']+)[\"']",
        Pattern.CASE_INSENSITIVE
    );

    private Map<String, String> parseModules(String js) {
        Map<String, String> modules = new LinkedHashMap<>();
        Matcher m = MODULE_PATTERN.matcher(js);
        while (m.find()) {
            String moduleName = m.group(1);
            String body = m.group(2);
            if (body.length() > MAX_MODULE_SIZE) {
                body = body.substring(0, MAX_MODULE_SIZE); // safety
            }
            modules.put(moduleName, body);
        }
        return modules;
    }

    private List<HarvestedGraphQLQuery> extractDirectArtifacts(String js, String sourceFile) {
        List<HarvestedGraphQLQuery> results = new ArrayList<>();

        // Extract tagged template literals (highest precision)
        Matcher tagMatcher = GRAPHQL_TAG.matcher(js);
        while (tagMatcher.find()) {
            String queryText = tagMatcher.group(1).trim();
            String operationName = extractOperationNameFromQuery(queryText);
            String operationType = detectOperationType(queryText);

            results.add(new HarvestedGraphQLQuery(
                operationName, operationType, null, queryText, sourceFile, "TAGGED_TEMPLATE"
            ));
        }

        Matcher hookMatcher = RELAY_HOOK.matcher(js);
        while (hookMatcher.find()) {
            String hookType = hookMatcher.group(1).toUpperCase();
            String operationName = hookMatcher.group(2);
            results.add(new HarvestedGraphQLQuery(
                operationName,
                hookType.contains("MUTATION") ? "MUTATION" : "QUERY",
                null, null, sourceFile, "RELAY_HOOK"
            ));
        }

        return results;
    }

    private List<HarvestedGraphQLQuery> extractFromModules(Map<String, String> modules, String sourceFile) {
        List<HarvestedGraphQLQuery> results = new ArrayList<>();
        Map<String, String> docIdToModule = new HashMap<>();

        for (Map.Entry<String, String> entry : modules.entrySet()) {
            String moduleName = entry.getKey();
            String body = entry.getValue();


            Matcher docMatcher = DOC_ID_EXPORT.matcher(body);
            if (docMatcher.find()) {
                String docId = docMatcher.group(1);
                docIdToModule.put(docId, moduleName);

                String opName = extractOperationNameFromModuleName(moduleName);
                String opType = detectOperationTypeFromModuleName(moduleName);

                String queryText = extractFullQueryText(body);

                results.add(new HarvestedGraphQLQuery(
                    opName, opType, docId, queryText, sourceFile, "META_MODULE"
                ));
            }

            if (moduleName.endsWith(".graphql") || moduleName.endsWith(".graphql.js")) {
                String queryText = extractFullQueryText(body);
                if (queryText != null && !queryText.isEmpty()) {
                    String opName = extractOperationNameFromQuery(queryText);
                    String opType = detectOperationType(queryText);

                    results.add(new HarvestedGraphQLQuery(
                        opName, opType, null, queryText, sourceFile, "GRAPHQL_MODULE"
                    ));
                }
            }
        }

        correlateDocIdsWithHooks(results, modules);

        return results;
    }

    private void correlateDocIdsWithHooks(List<HarvestedGraphQLQuery> results, Map<String, String> modules) {
        // Correlate Relay hooks with nearby doc_ids
        for (Map.Entry<String, String> entry : modules.entrySet()) {
            String moduleName = entry.getKey();
            if (!moduleName.endsWith(".react") && !moduleName.contains("Relay")) continue;

            String body = entry.getValue();
            Matcher hookMatcher = RELAY_HOOK.matcher(body);

            while (hookMatcher.find()) {
                String opName = hookMatcher.group(2);
                String nearbyDocId = findNearbyDocId(body, hookMatcher.start());
                if (nearbyDocId != null) {
                    for (HarvestedGraphQLQuery q : results) {
                        if (q.getDocId() != null && q.getDocId().equals(nearbyDocId)) {
                            q.setOperationName(opName);
                        }
                    }
                }
            }
        }
    }

    private String extractOperationNameFromQuery(String query) {
        Matcher m = Pattern.compile("(query|mutation|subscription)\\s+([A-Za-z0-9_]+)").matcher(query);
        return m.find() ? m.group(2) : "UnknownOperation";
    }

    private String detectOperationType(String query) {
        if (query.contains("mutation ")) return "MUTATION";
        if (query.contains("subscription ")) return "SUBSCRIPTION";
        return "QUERY";
    }

    private String extractOperationNameFromModuleName(String name) {
        name = name.replace(".graphql", "").replace(".js", "");
        String[] parts = name.split("[/\\\\]");
        return parts[parts.length - 1];
    }

    private String detectOperationTypeFromModuleName(String name) {
        if (name.contains("Mutation")) return "MUTATION";
        if (name.contains("Subscription")) return "SUBSCRIPTION";
        return "QUERY";
    }

    private String extractFullQueryText(String body) {
        Matcher m = GRAPHQL_TAG.matcher(body);
        if (m.find()) return m.group(1).trim();

        Matcher qm = Pattern.compile("(query|mutation|subscription)\\s+[A-Za-z0-9_]+[\\s\\S]{10,300}?\\}").matcher(body);
        return qm.find() ? qm.group(0) : null;
    }

    private String findNearbyDocId(String body, int position) {
        String window = body.substring(Math.max(0, position - 800), Math.min(body.length(), position + 400));
        Matcher m = DOC_ID_EXPORT.matcher(window);
        return m.find() ? m.group(1) : null;
    }

    public List<HarvestedGraphQLQuery> extractFromBundle(String js, String sourceFile) {
        if (js == null || js.length() < 100) return new ArrayList<>();

        List<HarvestedGraphQLQuery> all = new ArrayList<>();
        all.addAll(extractDirectArtifacts(js, sourceFile));
        Map<String, String> modules = parseModules(js);
        all.addAll(extractFromModules(modules, sourceFile));

        return deduplicate(all);
    }

    private List<HarvestedGraphQLQuery> deduplicate(List<HarvestedGraphQLQuery> list) {
        Set<String> seen = new HashSet<>();
        List<HarvestedGraphQLQuery> unique = new ArrayList<>();
        for (HarvestedGraphQLQuery q : list) {
            String key = q.getDocId() != null ? q.getDocId() : q.getOperationName() + "|" + q.getOperationType();
            if (seen.add(key)) {
                unique.add(q);
            }
        }
        return unique;
    }

    public static class HarvestedGraphQLQuery {
		// Fields and getters/setters...
        private String operationName;
        private String operationType;
        private String docId;
        private String queryText;
        private String sourceBundle;
        private String extractionMethod;

        public HarvestedGraphQLQuery(String operationName, String operationType, String docId,
                                     String queryText, String sourceBundle, String extractionMethod) {
            this.operationName = operationName;
            this.operationType = operationType;
            this.docId = docId;
            this.queryText = queryText;
            this.sourceBundle = sourceBundle;
            this.extractionMethod = extractionMethod;
        }

        public String getOperationName() { return operationName; }
        public String getOperationType() { return operationType; }
        public String getDocId() { return docId; }
        public String getQueryText() { return queryText; }
        public String getSourceBundle() { return sourceBundle; }
        public String getExtractionMethod() { return extractionMethod; }
        public void setOperationName(String name) { this.operationName = name; }
    }
}