package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {

        api.extension().setName("GraphQL Harvester - InMemory Edition");

        InMemoryEngine engine = new InMemoryEngine();
        api.http().registerHttpHandler(
            new HttpListener(api, engine)
        );

        api.userInterface().registerSuiteTab(
            "HarQL",
            new MainTab(api, engine)
        );

       // Register shutdown hook to autosave state
        api.extension().registerUnloadingHandler(() -> engine.shutdown());
    }
}