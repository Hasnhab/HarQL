package burp;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.*;
import java.nio.file.Files;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InMemoryEngine {

    private static final String DESKTOP = System.getProperty("user.home") + File.separator + "Desktop";
    private static final String BASE_DIR = DESKTOP + File.separator + "graphql_harvester";
    private static final String REPO_INDEX = BASE_DIR + File.separator + "index.json";
    private static final String AUTOSAVE_FILE = "autosave_rules.json";

    private static List<Map<String, Object>> repoItems = new ArrayList<>();
    private static Set<String> repoSeenDocids = new HashSet<>();
    private static List<Map<String, Object>> sessionItems = new ArrayList<>();
    private static Set<String> sessionSeenDocids = new HashSet<>();
	private Map<String, Object> originalVariablesSnapshot = new HashMap<>();

    private static Map<String, String> cacheDocByBase = new HashMap<>();
    private static Map<String, Map<String, Object>> cacheVarsByBase = new HashMap<>();
    private static Map<String, String> cacheModuleByBase = new HashMap<>();

    private static Map<String, Map<String, Object>> observedParams = new HashMap<>();
	private static Map<String, String> cacheReactModules = new HashMap<>();

    private final Map<String, Object> injectionRules = new LinkedHashMap<>();           // normKey → value
    private final Map<String, Map<String, Object>> presets = new LinkedHashMap<>();     // presetName → rulesMap

    private final Map<String, Map<String, Object>> originalRepoVars = new HashMap<>();
	private final GraphQLHarvesterService advancedHarvester = new GraphQLHarvesterService();
    private final Map<String, Map<String, Object>> originalSessionVars = new HashMap<>();

    private static final Pattern MODULE_BLOCK_RE = Pattern.compile(
    "__d\\(\\s*\"([^\"]+)\"\\s*,.*?\\(function\\([^\\)]*\\)\\s*\\{\\s*(.*?)\\s*\\}\\s*\\)\\s*,.*?\\)\\s*;",
    Pattern.DOTALL
    );
    private static final Pattern DOCID_EXPORT_RE = Pattern.compile("\\w+\\.exports\\s*=\\s*\"(\\d+)\"");
    private static final Pattern LOCAL_ARG_BLOCK_RE = Pattern.compile("\\{[^{}]*kind\\s*:\\s*\"LocalArgument\"[^{}]*\\}", Pattern.DOTALL);
    private static final Pattern NAME_IN_BLOCK_RE = Pattern.compile("name\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern DEFAULT_IN_BLOCK_RE = Pattern.compile("defaultValue\\s*:\\s*([^,\\}]+)");
    private static final Pattern VARIABLE_NAME_RE = Pattern.compile("variableName\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern ENTRYPOINT_PAIR_RE = Pattern.compile(
            "parameters\\s*:\\s*\\w\\(\\s*\"([^\"]+)\"\\s*\\)\\s*,[\\s\\S]*?variables\\s*:\\s*\\{([\\s\\S]*?)\\}\\s*[,}]",
            Pattern.DOTALL | Pattern.MULTILINE
    );
    private static final Pattern VAR_KEY_RE = Pattern.compile("([A-Za-z_][A-Za-z0-9_]*)\\s*:");

    public InMemoryEngine() {
        startup();
    }

    private void startup() {
        try {
            Files.createDirectories(Paths.get(BASE_DIR));
        } catch (IOException e) {
            throw new RuntimeException("Failed to create BASE_DIR", e);
        }

        repoItems = loadRepoIndex();
        repoSeenDocids.clear();
        for (Map<String, Object> item : repoItems) {
            if (item.containsKey("doc_id")) {
                String docId = (String) item.get("doc_id");
                repoSeenDocids.add(docId);
                @SuppressWarnings("unchecked")
                Map<String, Object> vars = (Map<String, Object>) item.get("variables");
                if (vars != null) originalRepoVars.put(docId, deepClone(vars));
            }
        }

        for (Map<String, Object> item : sessionItems) {
            if (item.containsKey("doc_id")) {
                String docId = (String) item.get("doc_id");
                @SuppressWarnings("unchecked")
                Map<String, Object> vars = (Map<String, Object>) item.get("variables");
                if (vars != null) originalSessionVars.put(docId, deepClone(vars));
            }
        }
         // Similar for sessionItems (if needed)

    }

    public void shutdown() {
        autosaveRules();
    }
	
/**
 * Exports current injection rules as JSON string.
 */
    public String exportRulesAsJson() {
        JSONObject json = new JSONObject();
        JSONObject rulesObj = new JSONObject();
        for (Map.Entry<String, Object> e : injectionRules.entrySet()) {
            rulesObj.put(e.getKey(), e.getValue());
        }
        json.put("rules", rulesObj);
        json.put("exported_at", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        return json.toString(2);
    }
/**
 * Imports injection rules from JSON string.
 * @throws RuntimeException if JSON is invalid
 */
 
    public void importRulesFromJson(String jsonText) {
        try {
            JSONObject json = new JSONObject(jsonText);
            if (json.has("rules")) {
                injectionRules.clear();
                JSONObject rulesObj = json.getJSONObject("rules");
                for (String k : rulesObj.keySet()) {
                    injectionRules.put(k, rulesObj.get(k));
                }
                autosaveRules();
            }
        } catch (Exception ex) {
            throw new RuntimeException("Invalid rules JSON", ex);
        }
    }

    public void addRule(String key, Object value) {
        String nk = normalizeKey(key);
        if (!nk.isEmpty()) {
            injectionRules.put(nk, value);
            autosaveRules();
        }
    }
	
/**
 * Returns insight about repeated variables across operations.
 */
 
    public List<Map<String, Object>> getRepeatedVariablesInsight() {
        List<Map<String, Object>> insight = new ArrayList<>();
        var observed = getObserved();

        for (var entry : observed.entrySet()) {
            String normKey = entry.getKey();
            Map<String, Object> meta = entry.getValue();

            @SuppressWarnings("unchecked")
            Map<Object, Integer> valueCount = (Map<Object, Integer>) meta.getOrDefault("values", new HashMap<>());

            if (valueCount.isEmpty()) continue;

            Object mostFreqValue = null;
            int maxFreq = 0;
            for (var f : valueCount.entrySet()) {
                if (f.getValue() > maxFreq) {
                    maxFreq = f.getValue();
                    mostFreqValue = f.getKey();
                }
            }
            // Total real occurrences (not unique value count)
            int totalCount = valueCount.values().stream().mapToInt(Integer::intValue).sum();

            Map<String, Object> row = new HashMap<>();
            row.put("parameter", normKey);
            row.put("count", totalCount);
            row.put("most_frequent_value", mostFreqValue);
            insight.add(row);
        }

        insight.sort((a, b) -> Integer.compare((Integer) b.get("count"), (Integer) a.get("count")));
        return insight;
    }
	private String normalizeKey(String key) {
        if (key == null) return "";
        return key.trim().toLowerCase().replaceAll("[^a-z0-9_\\.]", "");
    }
	public String exportVariablesAsBulkRules(Map<String, Object> variables) {
    StringBuilder sb = new StringBuilder();
    if (variables == null) return "";
    flattenVariables("", variables, sb);
    return sb.toString().trim();
}

private void flattenVariables(String prefix, Map<String, Object> map, StringBuilder sb) {
    for (Map.Entry<String, Object> entry : map.entrySet()) {
        String key = entry.getKey();
        Object value = entry.getValue();

        String fullKey = prefix.isEmpty() ? key : prefix + "." + key;

        if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> nested = (Map<String, Object>) value;
            flattenVariables(fullKey, nested, sb);
        } else if (value instanceof List) {
            flattenList(fullKey, (List<Object>) value, sb);
        } else {
            sb.append(normalizeKey(fullKey))
              .append("=")
              .append(formatRuleValue(value))
              .append("\n");
        }
    }
}
private void autosaveRules() {
    try {
        JSONObject obj = new JSONObject();
        obj.put("rules", injectionRules);

        Files.write(
            Paths.get(AUTOSAVE_FILE),
            obj.toString(2).getBytes(StandardCharsets.UTF_8)
        );
    } catch (Exception e) {
        System.err.println("Autosave failed: " + e.getMessage());
    }
}
private void loadAutosaveRules() {
    File file = new File(AUTOSAVE_FILE);
    if (!file.exists()) return;

    try {
        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        JSONObject obj = new JSONObject(content);

        injectionRules.clear();

        if (obj.has("rules")) {
            JSONObject rulesObj = obj.getJSONObject("rules");
            for (String key : rulesObj.keySet()) {
                injectionRules.put(normalizeKey(key), rulesObj.get(key));
            }
        }
    } catch (Exception e) {
        System.err.println("Autosave load failed: " + e.getMessage());
    }
}

private void flattenList(String prefix, List<Object> list, StringBuilder sb) {
    for (int i = 0; i < list.size(); i++) {
        Object item = list.get(i);
        String indexedKey = prefix + "[" + i + "]";
        if (item instanceof Map) {
            flattenVariables(indexedKey, (Map<String, Object>) item, sb);
        } else if (item instanceof List) {
            flattenList(indexedKey, (List<Object>) item, sb);
        } else {
            sb.append(normalizeKey(indexedKey))
              .append("=")
              .append(formatRuleValue(item))
              .append("\n");
        }
    }
}
public void addRulesFromVariables(Map<String, Object> variables) {
    String bulk = exportVariablesAsBulkRules(variables);
    if (bulk == null || bulk.isEmpty()) return;

    for (String line : bulk.split("\\r?\\n")) {
        if (!line.contains("=")) continue;
        int eq = line.indexOf('=');
        String key = line.substring(0, eq).trim();
        String val = line.substring(eq + 1).trim();
        injectionRules.put(normalizeKey(key), parseRuleValue(val));
    }
    autosaveRules();
}
private String formatRuleValue(Object val) {
    if (val == null) return "null";
    if (val instanceof String) return "\"" + val + "\"";
    return val.toString();
}
	public void applyInjectionToDataset(boolean isRepo) {

    if (injectionRules.isEmpty()) return;

    List<Map<String, Object>> target = isRepo ? repoItems : sessionItems;

    for (Map<String, Object> item : target) {

        @SuppressWarnings("unchecked")
        Map<String, Object> vars = (Map<String, Object>) item.get("variables");

        if (vars == null) continue;

        Map<String, Object> modified = deepClone(vars);
        applyInjectionRecursive(modified);

        item.put("variables", modified);
    }
 }
 public void applyInjectionToDatasetSafe(boolean isRepo) {
    resetAllToRaw(isRepo);
    applyInjectionToDataset(isRepo);
 }

    public void loadRules(String bulkText) {
        injectionRules.clear();
        if (bulkText == null || bulkText.trim().isEmpty()) return;

        for (String line : bulkText.split("\\r?\\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#") || !line.contains("=")) continue;

            int eq = line.indexOf('=');
            String key = line.substring(0, eq).trim();
            String valStr = line.substring(eq + 1).trim();

            String nk = normalizeKey(key);
            if (!nk.isEmpty()) {
                injectionRules.put(nk, parseRuleValue(valStr));
            }
        }
        autosaveRules();
    }

    private Object parseRuleValue(String s) {
        if (s == null) return null;
        s = s.trim();
        if (s.isEmpty() || "null".equalsIgnoreCase(s)) return null;
        if ("true".equalsIgnoreCase(s)) return true;
        if ("false".equalsIgnoreCase(s)) return false;

        try {
            if (s.matches("-?\\d+")) return Long.parseLong(s);
            if (s.matches("-?\\d+\\.\\d+")) return Double.parseDouble(s);
        } catch (Exception ignored) {}

        if ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'"))) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    public Map<String, Object> applyInjection(Map<String, Object> variables) {
        if (variables == null || injectionRules.isEmpty()) {
            return deepClone(variables);
        }
        Map<String, Object> copy = deepClone(variables);
        applyInjectionRecursive(copy);
        return copy;
    }

    private void applyInjectionRecursive(Map<String, Object> map) {
        if (map == null) return;
        for (Map.Entry<String, Object> entry : new ArrayList<>(map.entrySet())) {
            String norm = normalizeKey(entry.getKey());
            if (injectionRules.containsKey(norm)) {
                map.put(entry.getKey(), injectionRules.get(norm));
            }

            Object val = entry.getValue();
            if (val instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nested = (Map<String, Object>) val;
                applyInjectionRecursive(nested);
            } else if (val instanceof List) {
                applyInjectionToList((List<Object>) val);
            }
        }
    }

    private void applyInjectionToList(List<Object> list) {
        for (int i = 0; i < list.size(); i++) {
            Object item = list.get(i);
            if (item instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) item;
                applyInjectionRecursive(m);
            } else if (item instanceof List) {
                applyInjectionToList((List<Object>) item);
            }
        }
    }


    public void resetAllToRaw(boolean isRepo) {
        if (isRepo) {
            for (Map<String, Object> item : repoItems) {
                String docId = (String) item.get("doc_id");
                if (originalRepoVars.containsKey(docId)) {
                    item.put("variables", deepClone(originalRepoVars.get(docId)));
                }
            }
        } else {
            for (Map<String, Object> item : sessionItems) {
                String docId = (String) item.get("doc_id");
                if (originalSessionVars.containsKey(docId)) {
                    item.put("variables", deepClone(originalSessionVars.get(docId)));
                }
            }
        }
    }
	

    public void clearAllRules() {
        injectionRules.clear();
        autosaveRules();
    }

    public void savePreset(String name, String bulkText) {
        if (name == null || name.trim().isEmpty()) return;
        loadRules(bulkText);
        Map<String, Object> ruleCopy = new LinkedHashMap<>(injectionRules);
        presets.put(name.trim(), ruleCopy);
        autosaveRules();
    }



	public String getRulesAsBulkText() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Object> e : injectionRules.entrySet()) {
            Object val = e.getValue();
            String valueStr = (val == null) ? "null" : 
                             (val instanceof String) ? "\"" + val + "\"" : val.toString();
            sb.append(e.getKey()).append("=").append(valueStr).append("\n");
        }
        return sb.toString().trim();
    }

    private Map<String, Object> deepClone(Map<String, Object> original) {
        if (original == null) return null;
        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : original.entrySet()) {
            Object v = e.getValue();
            if (v instanceof Map) copy.put(e.getKey(), deepClone((Map<String, Object>) v));
            else if (v instanceof List) copy.put(e.getKey(), deepCloneList((List<Object>) v));
            else copy.put(e.getKey(), v);
        }
        return copy;
    }

    private List<Object> deepCloneList(List<Object> original) {
        List<Object> copy = new ArrayList<>();
        for (Object o : original) {
            if (o instanceof Map) copy.add(deepClone((Map<String, Object>) o));
            else if (o instanceof List) copy.add(deepCloneList((List<Object>) o));
            else copy.add(o);
        }
        return copy;
    }

    private boolean upsertRepo(String docid, Map<String, Object> variables, String module, String ts, String host, String src) {
        for (Map<String, Object> it : repoItems) {
            if (!docid.equals(it.get("doc_id"))) continue;
            if (!originalRepoVars.containsKey(docid) && variables != null && !variables.isEmpty()) {
    originalRepoVars.put(docid, deepClone(variables));
 }
            it.put("variables", mergeVars((Map<String, Object>) it.get("variables"), variables));
            if (module != null && !module.isEmpty()) it.put("module", module);
            if (ts != null && !ts.isEmpty()) it.put("ts", ts);
            if (host != null && !host.isEmpty()) {
                Object existing = it.get("host");
                if (existing == null || existing.toString().isEmpty()) it.put("host", host);
            }
            if (src != null && !src.isEmpty()) {
                Object existing = it.get("src");
                if (existing == null || existing.toString().isEmpty()) it.put("src", src);
            }
            return false;
        }
        Map<String, Object> newItem = new HashMap<>();
        newItem.put("doc_id", docid);
        newItem.put("variables", variables != null ? variables : new HashMap<>());
        newItem.put("module", module != null ? module : "");
        newItem.put("ts", ts != null ? ts : "");
        newItem.put("host", host != null ? host : "");
        newItem.put("src", src != null ? src : "");
        repoItems.add(newItem);
		if (variables != null && !variables.isEmpty()) {
    originalRepoVars.put(docid, deepClone(variables));
}
        repoSeenDocids.add(docid);
        return true;
    }

    private boolean upsertSession(String docid, Map<String, Object> variables, String module, String ts, String host, String src) {
        for (Map<String, Object> it : sessionItems) {
            if (docid.equals(it.get("doc_id"))) {
                if (!originalSessionVars.containsKey(docid) && variables != null) {
    originalSessionVars.put(docid, deepClone(variables));
 }
                it.put("variables", mergeVars((Map<String, Object>) it.getOrDefault("variables", new HashMap<>()), variables));
                if (module != null && !module.isEmpty()) it.put("module", module);
                if (ts != null && !ts.isEmpty()) it.put("ts", ts);
                if (host != null && !host.isEmpty()) {
                    Object existing = it.get("host");
                    if (existing == null || existing.toString().isEmpty()) it.put("host", host);
                }
                if (src != null && !src.isEmpty()) {
                    Object existing = it.get("src");
                    if (existing == null || existing.toString().isEmpty()) it.put("src", src);
                }
                return false;
            }
        }
        if (!sessionSeenDocids.contains(docid)) {
            sessionSeenDocids.add(docid);
            Map<String, Object> newItem = new HashMap<>();
            newItem.put("doc_id", docid);
            newItem.put("variables", variables != null ? variables : new HashMap<>());
            newItem.put("module", module != null ? module : "");
            newItem.put("ts", ts != null ? ts : "");
            newItem.put("host", host != null ? host : "");
            newItem.put("src", src != null ? src : "");
            sessionItems.add(newItem);
			if (variables != null && !variables.isEmpty()) {
    originalSessionVars.put(docid, deepClone(variables));
}
            return true;
        }
        return false;
    }

    private List<Map<String, Object>> loadRepoIndex() {
        if (!new File(REPO_INDEX).exists()) return new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(REPO_INDEX))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            JSONObject json = new JSONObject(sb.toString());
            JSONArray data = json.getJSONArray("items");
            List<Map<String, Object>> items = new ArrayList<>();
            for (int i = 0; i < data.length(); i++) {
                JSONObject it = data.getJSONObject(i);
                Map<String, Object> map = jsonToMap(it);
                if (!map.containsKey("host")) map.put("host", "");
                if (!map.containsKey("src")) map.put("src", "");
                items.add(map);
            }
            return items;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    private void saveRepoIndex(List<Map<String, Object>> items) {
        JSONArray safeItems = new JSONArray();
        for (Map<String, Object> it : items) {
            JSONObject safe = new JSONObject();
            safe.put("doc_id", it.get("doc_id"));
            safe.put("variables", mapToJson((Map<String, Object>) it.getOrDefault("variables", new HashMap<>())));
            safe.put("module", it.getOrDefault("module", ""));
            safe.put("ts", it.getOrDefault("ts", ""));
            safe.put("host", it.getOrDefault("host", ""));
            safe.put("src", it.getOrDefault("src", ""));
            safeItems.put(safe);
        }
        JSONObject jsonData = new JSONObject();
        jsonData.put("items", safeItems);
        try (FileWriter fw = new FileWriter(REPO_INDEX)) {
            fw.write(jsonData.toString(2));
        } catch (IOException e) {
            throw new RuntimeException("Failed to save repo index", e);
        }
    }

    private Map<String, Object> mergeVars(Map<String, Object> existing, Map<String, Object> newVars) {
        if (existing == null || existing.isEmpty())
    return newVars != null ? new HashMap<>(newVars) : new HashMap<>();
        if (newVars == null || newVars.isEmpty()) return new HashMap<>(existing);
        Map<String, Object> merged = new HashMap<>(existing);
        for (Map.Entry<String, Object> entry : newVars.entrySet()) {
            String k = entry.getKey();
            Object v = entry.getValue();
            if ("input".equals(k) && v instanceof Map && merged.containsKey("input") && merged.get("input") instanceof Map) {
                merged.put("input", mergeVars((Map<String, Object>) merged.get("input"), (Map<String, Object>) v));
            } else if (!merged.containsKey(k) || merged.get(k) == null) {
                merged.put(k, v);
            }
        }
        return merged;
    }

    private Map<String, Object> jsonToMap(JSONObject json) throws JSONException {
        Map<String, Object> map = new HashMap<>();
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = json.get(key);
            if (value instanceof JSONObject) value = jsonToMap((JSONObject) value);
            else if (value instanceof JSONArray) value = jsonToList((JSONArray) value);
            else if (value == JSONObject.NULL) value = null;
            map.put(key, value);
        }
        return map;
    }

    private List<Object> jsonToList(JSONArray array) throws JSONException {
        List<Object> list = new ArrayList<>();
        for (int i = 0; i < array.length(); i++) {
            Object value = array.get(i);
            if (value instanceof JSONObject) value = jsonToMap((JSONObject) value);
            else if (value instanceof JSONArray) value = jsonToList((JSONArray) value);
            else if (value == JSONObject.NULL) value = null;
            list.add(value);
        }
        return list;
    }

    private JSONObject mapToJson(Map<String, Object> map) {
        JSONObject json = new JSONObject();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object v = entry.getValue();
            if (v instanceof Map) v = mapToJson((Map<String, Object>) v);
            else if (v instanceof List) v = listToJson((List<Object>) v);
            else if (v == null) v = JSONObject.NULL;
            json.put(entry.getKey(), v);
        }
        return json;
    }

    private JSONArray listToJson(List<Object> list) {
        JSONArray array = new JSONArray();
        for (Object o : list) {
            if (o instanceof Map) o = mapToJson((Map<String, Object>) o);
            else if (o instanceof List) o = listToJson((List<Object>) o);
            else if (o == null) o = JSONObject.NULL;
            array.put(o);
        }
        return array;
    }

    private Map<String, String> extractModules(String text) {
        Map<String, String> modules = new HashMap<>();
        Matcher matcher = MODULE_BLOCK_RE.matcher(text);
        while (matcher.find()) {
            String name = matcher.group(1);
            String body = matcher.group(2);
            modules.put(name, body);
            
            if (name.endsWith(".react")) {
                cacheReactModules.put(name, body);
            }
        }
        return modules;
    }

    private String baseNameFromOperation(String moduleName) {
        if (moduleName.endsWith("_facebookRelayOperation")) {
            return moduleName.substring(0, moduleName.length() - "_facebookRelayOperation".length());
        }
        return null;
    }

    private Object normalizeDefaultToken(String token) {
        if (token == null) return null;
        String s = token.trim();
        if ("!0".equals(s)) return false;
        if ("!1".equals(s)) return true;
        if ("null".equalsIgnoreCase(s)) return null;
        if ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'"))) {
            return s.substring(1, s.length() - 1);
        }
        if (Pattern.compile("WebPixelRatio\\.get\\(\\)", Pattern.DOTALL).matcher(s).find()) return 1;
        if (Pattern.matches("-?\\d+", s)) {
            try {
                return Long.parseLong(s);
            } catch (NumberFormatException e) {
                return s;
            }
        }
        if ("true".equals(s)) return true;
        if ("false".equals(s)) return false;
        return null;
    }

    private Map<String, Object> collectVariablesFromGraphql(String graphqlBody) {
        Set<String> names = new HashSet<>();
        Matcher varMatcher = VARIABLE_NAME_RE.matcher(graphqlBody);
        while (varMatcher.find()) {
            names.add(varMatcher.group(1));
        }
        Map<String, Object> defaultsMap = new HashMap<>();
        Matcher blockMatcher = LOCAL_ARG_BLOCK_RE.matcher(graphqlBody);
        while (blockMatcher.find()) {
            String block = blockMatcher.group();
            String nm = null;
            Object dv = null;
            Matcher nameMatcher = NAME_IN_BLOCK_RE.matcher(block);
            if (nameMatcher.find()) {
                nm = nameMatcher.group(1);
                names.add(nm);
            }
            Matcher defMatcher = DEFAULT_IN_BLOCK_RE.matcher(block);
            if (defMatcher.find()) {
                dv = normalizeDefaultToken(defMatcher.group(1));
            }
            if (nm != null) {
                defaultsMap.put(nm, dv);
            }
        }
        List<String> sortedNames = new ArrayList<>(names);
        Collections.sort(sortedNames);
        Map<String, Object> variables = new LinkedHashMap<>();
        for (String n : sortedNames) {
            variables.put(n, defaultsMap.containsKey(n) ? defaultsMap.get(n) : null);
        }
        return variables;
    }

    private Object inferDefaultForKeyFromVarblock(String varKey, String varBlock) {
        Pattern p = Pattern.compile(Pattern.quote(varKey) + "\\s*:\\s*(.+?)(?:,|\\n|\\})", Pattern.DOTALL);
        Matcher m = p.matcher(varBlock);
        if (!m.find()) return null;
        String token = m.group(1).trim();
        Pattern ternP = Pattern.compile("\\?\\s*[^:]+:\\s*(.+)$");
        Matcher ternM = ternP.matcher(token);
        if (ternM.find()) {
            Object dv = normalizeDefaultToken(ternM.group(1));
            if (dv != null) return dv;
        }
        return normalizeDefaultToken(token);
    }

    private Map<String, Object> collectVariablesFromEntrypoint(String entryBody, String baseName) {
        Map<String, Object> variables = new HashMap<>();
        if (entryBody == null || entryBody.isEmpty()) return variables;

        Matcher pairMatcher = ENTRYPOINT_PAIR_RE.matcher(entryBody);
        while (pairMatcher.find()) {
            String paramsName = pairMatcher.group(1);
            String varBlock = pairMatcher.group(2).trim();

            if ((baseName + "$Parameters").equals(paramsName)) {
                Matcher keyMatcher = VAR_KEY_RE.matcher(varBlock);
                while (keyMatcher.find()) {
                    String k = keyMatcher.group(1);
                    if (!variables.containsKey(k)) {
                        variables.put(k, inferDefaultForKeyFromVarblock(k, varBlock));
                    }
                }
                break;
            }
        }

        Pattern nestedInputRe = Pattern.compile("variables\\s*:\\s*\\{\\s*input\\s*:\\s*\\{\\s*([\\s\\S]*?)\\}\\s*\\}", Pattern.DOTALL);
        Matcher nestedMatcher = nestedInputRe.matcher(entryBody);
        if (nestedMatcher.find()) {
            String inputBlock = nestedMatcher.group(1).trim();
            Map<String, Object> inputVars = new HashMap<>();
            Matcher inputKeyMatcher = VAR_KEY_RE.matcher(inputBlock);
            while (inputKeyMatcher.find()) {
                String k = inputKeyMatcher.group(1);
                if (!inputVars.containsKey(k)) {
                    inputVars.put(k, inferDefaultForKeyFromVarblock(k, inputBlock));
                }
            }
            if (!inputVars.isEmpty()) {
                variables.put("input", inputVars);
            }
        }

        return variables;
    }

    private Map<String, Object> collectVariablesFromParametersBlocks(String fullText, String baseName) {
        return collectVariablesFromEntrypoint(fullText, baseName);
    }
    private String deriveReactName(String graphqlName) {
        if (graphqlName == null) return null;
        if (graphqlName.endsWith("_syncMutation.graphql")) {
            String prefix = graphqlName.substring(0, graphqlName.length() - "_syncMutation.graphql".length());
            return prefix + ".react";
        }
        if (graphqlName.endsWith("Mutation.graphql")) {
            String prefix = graphqlName.substring(0, graphqlName.length() - "Mutation.graphql".length());
            return prefix + ".react";
        }
        return null;
    }

    private boolean isInputMutation(String body) {
        if (body == null) return false;
        return body.contains("variableName: \"input\"") || body.contains("variableName: 'input'");
    }

    private String extractBalancedObject(String text, int startPos) {
        if (startPos >= text.length() || text.charAt(startPos) != '{') return null;
        StringBuilder sb = new StringBuilder("{");
        int count = 1, i = startPos + 1;
        boolean inString = false, escape = false;
        char quote = 0;
        while (i < text.length() && count > 0) {
            char c = text.charAt(i);
            if (escape) { escape = false; } 
            else if (c == '\\') { escape = true; }
            else if (c == '"' || c == '\'') {
                if (!inString) { quote = c; inString = true; }
                else if (c == quote) inString = false;
            }
            else if (!inString) {
                if (c == '{') count++;
                else if (c == '}') count--;
            }
            sb.append(c);
            i++;
        }
        return (count == 0) ? sb.toString() : null;
    }

    private Map<String, Object> parseInputStructure(String objStr) {
        if (objStr == null || !objStr.trim().startsWith("{")) return new HashMap<>();
        Map<String, Object> structure = new LinkedHashMap<>();
        Matcher keyMatcher = VAR_KEY_RE.matcher(objStr);
        while (keyMatcher.find()) {
            String key = keyMatcher.group(1);
            int afterColon = keyMatcher.end();
            int nextBrace = objStr.indexOf('{', afterColon);
            if (nextBrace != -1 && nextBrace < afterColon + 100) {
                String nested = extractBalancedObject(objStr, nextBrace);
                if (nested != null) {
                    structure.put(key, parseInputStructure(nested));
                    continue;
                }
            }
            structure.put(key, null);
        }
        return structure;
    }

    private Map<String, Object> extractInputFromReact(String reactBody) {
        if (reactBody == null || reactBody.isEmpty()) return new HashMap<>();
        Pattern[] patterns = {
            Pattern.compile("variables\\s*:\\s*\\{[^}]*input\\s*:\\s*(\\{[\\s\\S]*?\\})", Pattern.DOTALL),
            Pattern.compile("variables\\s*:\\s*\\{\\s*input\\s*:\\s*(\\{[\\s\\S]*?\\})", Pattern.DOTALL),
            Pattern.compile("input\\s*:\\s*(\\{[\\s\\S]*?\\})\\s*[,}]", Pattern.DOTALL),
            Pattern.compile("input:\\s*(\\{[\\s\\S]*?\\})", Pattern.DOTALL)
        };
        for (Pattern p : patterns) {
            Matcher m = p.matcher(reactBody);
            while (m.find()) {
                String obj = m.group(1);
                if (obj != null && obj.trim().startsWith("{")) {
                    Map<String, Object> inputStruct = parseInputStructure(obj);
                    if (!inputStruct.isEmpty()) {
                        Map<String, Object> res = new HashMap<>();
                        res.put("input", inputStruct);
                        return res;
                    }
                }
            }
        }
        return new HashMap<>();
    }
    
    public List<GraphQLHarvesterService.HarvestedGraphQLQuery> getAdvancedHarvestedQueries(String jsBundle) {
    return advancedHarvester.extractFromBundle(jsBundle, "live_bundle");
    }
    private Map<String, Map<String, Object>> harvestFromText(String txt) {
    if (txt == null || txt.isEmpty()) {
        return new HashMap<>();
    }

    String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

    List<GraphQLHarvesterService.HarvestedGraphQLQuery> advancedQueries = 
    advancedHarvester.extractFromBundle(txt, "current_bundle");

    Map<String, String> modules = extractModules(txt);
    Map<String, String> localDocByBase = new HashMap<>();

    for (Map.Entry<String, String> entry : modules.entrySet()) {
        String name = entry.getKey();
        String body = entry.getValue();
        String base = baseNameFromOperation(name);
        if (base == null) continue;

        Matcher docMatcher = DOCID_EXPORT_RE.matcher(body);
        if (docMatcher.find()) {
            String docid = docMatcher.group(1);
            localDocByBase.put(base, docid);
            cacheDocByBase.put(base, docid);
            cacheModuleByBase.put(base, base);
        }
    }

    for (Map.Entry<String, String> entry : modules.entrySet()) {
        String name = entry.getKey();
        String body = entry.getValue();
        if (name.endsWith(".graphql")) {
            String base = name.substring(0, name.length() - ".graphql".length());
            Map<String, Object> varsGraphql = collectVariablesFromGraphql(body);

            if (isInputMutation(body) &&
               (name.endsWith("_syncMutation.graphql") || name.endsWith("Mutation.graphql"))) {
                String reactName = deriveReactName(name);
                if (reactName != null) {
                    String reactBody = getReactBody(modules, reactName, txt);
                    if (reactBody != null) {
                        Map<String, Object> inputStruct = extractInputFromReact(reactBody);
                        if (!inputStruct.isEmpty()) {
                            varsGraphql = inputStruct;
                        }
                    }
                }
            }
            cacheVarsByBase.put(base, mergeVars(cacheVarsByBase.getOrDefault(base, new HashMap<>()), varsGraphql));
            cacheModuleByBase.put(base, base);
        }
    }

    processEntrypointBlocks(modules, txt);

    Map<String, Map<String, Object>> pairs = new HashMap<>();

    for (GraphQLHarvesterService.HarvestedGraphQLQuery q : advancedQueries) {
        if (q.getDocId() == null) continue;

        String docId = q.getDocId();
        Map<String, Object> rec = pairs.computeIfAbsent(docId, k -> new HashMap<>());
        rec.put("doc_id", docId);
        rec.put("module", q.getOperationName());
        rec.put("ts", ts);
        rec.put("src", "advanced_harvester");

        String base = getBaseFromDocId(docId);
        Map<String, Object> variables = (base != null) 
            ? new HashMap<>(cacheVarsByBase.getOrDefault(base, new HashMap<>()))
            : new HashMap<>();

        if (variables.isEmpty() && q.getQueryText() != null) {
            variables = collectVariablesFromGraphql(q.getQueryText());
        }
        rec.put("variables", variables);
    }

    for (Map.Entry<String, String> entry : localDocByBase.entrySet()) {
        String base = entry.getKey();
        String docId = entry.getValue();
        if (pairs.containsKey(docId)) continue;

        Map<String, Object> variables = new HashMap<>(cacheVarsByBase.getOrDefault(base, new HashMap<>()));

        if (isInputCase(base, modules)) {
            Map<String, Object> cached = cacheVarsByBase.get(base);
            if (cached != null && cached.containsKey("input") && cached.get("input") instanceof Map) {
                variables = new HashMap<>(cached);
            }
        }

        Map<String, Object> rec = new HashMap<>();
        rec.put("doc_id", docId);
        rec.put("variables", variables);
        rec.put("module", cacheModuleByBase.getOrDefault(base, base));
        rec.put("ts", ts);
        rec.put("src", "traditional_fallback");
        pairs.put(docId, rec);
    }

    return pairs;
}


private String getReactBody(Map<String, String> modules, String reactName, String fullText) {
    if (modules.containsKey(reactName)) return modules.get(reactName);
    if (cacheReactModules.containsKey(reactName)) return cacheReactModules.get(reactName);

    Pattern reactP = Pattern.compile(
        "__d\\(\\s*\"" + Pattern.quote(reactName) + "\"\\s*,.*?\\(function\\([^\\)]*\\)\\s*\\{\\s*(.*?)\\s*\\}\\s*\\)\\s*,",
        Pattern.DOTALL);
    Matcher m = reactP.matcher(fullText);
    return m.find() ? m.group(1) : null;
}

private String getBaseFromDocId(String docId) {
    for (Map.Entry<String, String> e : cacheDocByBase.entrySet()) {
        if (docId.equals(e.getValue())) {
            return e.getKey();
        }
    }
    return null;
}

private boolean isInputCase(String base, Map<String, String> modules) {
    String graphqlName = base + ".graphql";
    if (!modules.containsKey(graphqlName)) return false;
    String body = modules.get(graphqlName);
    return isInputMutation(body) &&
           (graphqlName.endsWith("_syncMutation.graphql") || graphqlName.endsWith("Mutation.graphql"));
}

private void processEntrypointBlocks(Map<String, String> modules, String txt) {
    for (Map.Entry<String, String> entry : modules.entrySet()) {
        String name = entry.getKey();
        String body = entry.getValue();
        if (name.endsWith(".entrypoint")) {
            String base = name.substring(0, name.length() - ".entrypoint".length());
            Map<String, Object> variables = collectVariablesFromEntrypoint(body, base);
            if (!variables.isEmpty()) {
                cacheVarsByBase.put(base, mergeVars(cacheVarsByBase.getOrDefault(base, new HashMap<>()), variables));
                cacheModuleByBase.put(base, base);
            }
        }
    }

    Matcher globalPairMatcher = ENTRYPOINT_PAIR_RE.matcher(txt);
    while (globalPairMatcher.find()) {
        String paramsName = globalPairMatcher.group(1);
        String varBlock = globalPairMatcher.group(2);
        if (paramsName.endsWith("$Parameters")) {
            String base = paramsName.substring(0, paramsName.length() - "$Parameters".length());
            Map<String, Object> variables = new HashMap<>();
            Matcher keyMatcher = VAR_KEY_RE.matcher(varBlock);
            while (keyMatcher.find()) {
                String k = keyMatcher.group(1);
                variables.put(k, inferDefaultForKeyFromVarblock(k, varBlock));
            }
            if (!variables.isEmpty()) {
                cacheVarsByBase.put(base, mergeVars(cacheVarsByBase.getOrDefault(base, new HashMap<>()), variables));
                cacheModuleByBase.put(base, base);
            }
        }
    }
 }
    private List<Map<String, Object>> parseGraphqlVariablesFromBody(String reqText) {
    List<Map<String, Object>> out = new ArrayList<>();
    if (reqText == null || reqText.isEmpty()) return out;

    try {
        JSONObject obj = new JSONObject(reqText);
        Object varsField = obj.opt("variables");
        if (varsField instanceof JSONObject) {
            out.add(jsonToMap((JSONObject) varsField));
        } else if (varsField instanceof String) {
            try {
                JSONObject parsed = new JSONObject((String) varsField);
                out.add(jsonToMap(parsed));
            } catch (JSONException ignored) {}
        }
    } catch (JSONException ignored) {}

    try {
        JSONArray listObj = new JSONArray(reqText);
        for (int i = 0; i < listObj.length(); i++) {
            JSONObject item = listObj.getJSONObject(i);
            Object v = item.opt("variables");
            if (v instanceof JSONObject) out.add(jsonToMap((JSONObject) v));
            else if (v instanceof String) {
                try { out.add(jsonToMap(new JSONObject((String) v))); } catch (JSONException ignored) {}
            }
        }
    } catch (JSONException ignored) {}

    Map<String, List<String>> qs = parseQueryString(reqText);
    List<String> varsList = qs.getOrDefault("variables", new ArrayList<>());
    for (String encodedVar : varsList) {
        try {
            String decoded = java.net.URLDecoder.decode(encodedVar, StandardCharsets.UTF_8);
            JSONObject parsed = new JSONObject(decoded);
            out.add(jsonToMap(parsed));
        } catch (Exception ignored) {}
    }

    return out;
}
	private Map<String, List<String>> parseQueryString(String query) {
        Map<String, List<String>> params = new HashMap<>();
        if (query == null || query.isEmpty()) return params;
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            String key = idx > 0 ? pair.substring(0, idx) : pair;
            String value = idx > 0 && pair.length() > idx + 1 ? pair.substring(idx + 1) : "";
            params.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
        }
        return params;
    }
    private void observedAddFromDict(Map<String, Object> varsObj) {
        for (Map.Entry<String, Object> entry : varsObj.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            Map<String, Object> meta = observedParams.computeIfAbsent(key, k -> new HashMap<>());

            @SuppressWarnings("unchecked")
            Map<Object, Integer> valueCount = (Map<Object, Integer>) meta
                    .computeIfAbsent("values", k -> new HashMap<>());

            valueCount.put(value, valueCount.getOrDefault(value, 0) + 1);
        }
    }

    private Map<String, Map<String, Object>> observedSnapshot() {
        return new HashMap<>(observedParams);
    }

    public Map<String, Object> ingestJs(String url, String host, String body) {
        Map<String, Map<String, Object>> pairs = harvestFromText(body);
        boolean updatedRepo = false;
        boolean updatedSession = false;
        for (Map.Entry<String, Map<String, Object>> entry : pairs.entrySet()) {
            String docid = entry.getKey();
            Map<String, Object> rec = entry.getValue();
            Map<String, Object> variables = (Map<String, Object>) rec.get("variables");
            String module = (String) rec.get("module");
            String ts = (String) rec.get("ts");
            updatedRepo |= upsertRepo(docid, variables, module, ts, host, url);
            updatedSession |= upsertSession(docid, variables, module, ts, host, url);
        }
        if (updatedRepo) {
            saveRepoIndex(repoItems);
        }
        Map<String, Object> result = new HashMap<>();
        result.put("repo_updated", updatedRepo);
        result.put("session_updated", updatedSession);
        result.put("items", pairs.size());
        return result;
    }

    public Map<String, Object> ingestGraphql(String body, String queryString, Map<String, String> headers) {
        String reqText = body != null && !body.isEmpty() ? body : queryString;
        List<Map<String, Object>> varsSets = parseGraphqlVariablesFromBody(reqText);
        for (Map<String, Object> varsObj : varsSets) {
            observedAddFromDict(varsObj);
        }
        Map<String, Object> result = new HashMap<>();
        result.put("observed_sets", varsSets.size());
        return result;
    }

    public List<Map<String, Object>> getRepo() {
        return new ArrayList<>(repoItems);
    }

    public List<Map<String, Object>> getSession() {
        return new ArrayList<>(sessionItems);
    }

    public Map<String, Map<String, Object>> getObserved() {
        return observedSnapshot();
    }

    public List<Map<String, Object>> intelligenceNotes() {
        List<Map<String, Object>> notes = new ArrayList<>();
        Map<String, Map<String, Object>> observed = observedSnapshot();
        List<Map<String, Object>> repo = getRepo();
        for (Map.Entry<String, Map<String, Object>> entry : observed.entrySet()) {
            String key = entry.getKey();
            Map<String, Object> meta = entry.getValue();
            Set<String> ops = new HashSet<>();
            for (Map<String, Object> it : repo) {
                Map<String, Object> vars = (Map<String, Object>) it.get("variables");
                if (vars != null && vars.containsKey(key)) {
                    ops.add((String) it.get("doc_id"));
                }
            }
            if (ops.size() > 1) {
                Map<String, Object> note = new HashMap<>();
                note.put("key", key);
                note.put("type", "Cross-Operation Parameter");
                note.put("count", ops.size());
                notes.add(note);
            }
            if (meta.containsKey("values") && meta.containsKey("defaults")) {
                Map<String, Object> note = new HashMap<>();
                note.put("key", key);
                note.put("type", "Default Override Observed");
                notes.add(note);
            }
        }
        return notes;
    }

    public Map<String, Object> health() {
        Map<String, Object> result = new HashMap<>();
        result.put("status", "running");
        result.put("since", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        return result;
    }

    public Map<String, Object> stats() {
        Map<String, Object> result = new HashMap<>();
        result.put("repo_items", repoItems.size());
        result.put("session_items", sessionItems.size());
        result.put("observed_keys", observedParams.size());
        result.put("engine_since", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
        return result;
    }

    public Map<String, Object> clearSession() {
        sessionItems.clear();
        sessionSeenDocids.clear();
        observedParams.clear();
		originalSessionVars.clear();
        Map<String, Object> result = new HashMap<>();
        result.put("status", "session_cleared");
        return result;
    }

    public Map<String, Object> reloadRepo() {
    repoItems = loadRepoIndex();
    repoSeenDocids = new HashSet<>();
    originalRepoVars.clear();

    for (Map<String, Object> it : repoItems) {
        String docId = (String) it.get("doc_id");
        repoSeenDocids.add(docId);

        @SuppressWarnings("unchecked")
        Map<String, Object> vars = (Map<String, Object>) it.get("variables");
        if (vars != null) {
            originalRepoVars.put(docId, deepClone(vars));
        }
    }

    Map<String, Object> result = new HashMap<>();
    result.put("status", "repo_reloaded");
    return result;
 }


    public static void main(String[] args) {
        InMemoryEngine engine = new InMemoryEngine();
        System.out.println(engine.health());
    }
}