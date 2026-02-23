package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

public class GraphQLSchemaBuilder {

    private final Map<String, Map<String, String>> operations = new HashMap<>();
/**
 * Builds an inferred GraphQL SDL schema from harvested operations.
 *
 * @param repoList list of harvested GraphQL items
 * @return SDL string
 */
    public String buildSDL(List<Map<String, Object>> repoList) {
        StringBuilder sdl = new StringBuilder();
        sdl.append("# Inferred GraphQL Schema – based on harvested operations\n");
        sdl.append("# Generated: ").append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n\n");

        try {
            for (Map<String, Object> item : repoList) {
                String module = (String) item.getOrDefault("module", "UnknownOperation_" + System.nanoTime());
                @SuppressWarnings("unchecked")
                Map<String, Object> variables = (Map<String, Object>) item.get("variables");

                if (variables != null && !variables.isEmpty()) {
                    Map<String, String> args = operations.computeIfAbsent(module, k -> new LinkedHashMap<>());
                    inferArguments(variables, args, "");
                }
            }

            sdl.append("type Query {\n");
            for (String op : operations.keySet()) {
                String clean = sanitizeName(op);
                sdl.append("  ").append(clean)
                   .append("(input: ").append(clean).append("Input): ")
                   .append(clean).append("Result\n");
            }
            sdl.append("}\n\n");

            for (Map.Entry<String, Map<String, String>> op : operations.entrySet()) {
                String opName = sanitizeName(op.getKey());
                sdl.append("input ").append(opName).append("Input {\n");
                for (Map.Entry<String, String> arg : op.getValue().entrySet()) {
                    sdl.append("  ").append(arg.getKey()).append(": ").append(arg.getValue()).append("\n");
                }
                sdl.append("}\n\n");

                sdl.append("type ").append(opName).append("Result {\n");
                sdl.append("  # Inferred – extend manually\n");
                sdl.append("}\n\n");
            }

        } catch (Exception e) {
            sdl.append("# Error building schema: ").append(e.getMessage());
        }

        return sdl.toString();
    }

    private void inferArguments(Map<String, Object> vars, Map<String, String> args, String prefix) {
        for (Map.Entry<String, Object> entry : vars.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            String type = inferType(value);
            String fieldName = prefix.isEmpty() ? key : prefix + capitalize(key);
            args.put(fieldName, type);
        }
    }

    private String inferType(Object value) {
        if (value == null) return "String";
        if (value instanceof Integer || value instanceof Long) return "Int";
        if (value instanceof Float || value instanceof Double) return "Float";
        if (value instanceof Boolean) return "Boolean";
        if (value instanceof String) return "String";
        if (value instanceof List) {
            List<?> list = (List<?>) value;
            return list.isEmpty() ? "[String]" : "[" + inferType(list.get(0)) + "]";
        }
        if (value instanceof Map) return "Object";
        return "String";
    }

    private String capitalize(String str) {
        if (str.isEmpty()) return str;
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }

    private String sanitizeName(String name) {
        return name.replaceAll("[^a-zA-Z0-9_]", "_");
    }

/**
 * Returns the extracted operations and their argument types.
 *
 * @return map of operation name → argument name → inferred type
 */
    public Map<String, Map<String, String>> getOperationsData() {
        return new HashMap<>(operations);
    }
}