# HarQL

**Advanced In-Memory GraphQL Harvester for Burp Suite**

HarQL is a powerful Burp Suite extension that extracts GraphQL operations, `doc_id`s, and variables from JavaScript bundles and live traffic **without requiring introspection**.

It is currently **highly specialized** for Meta platforms (Facebook, Instagram, etc.) thanks to its advanced regex engine optimized for their specific obfuscation patterns and Relay architecture. Future versions will expand support to any GraphQL environment.

---

## Key Features

- **No Introspection Required** — Works even when introspection is disabled or restricted
- **Advanced JS Bundle Parsing** — Extracts from large, heavily obfuscated JavaScript files (optimized for Meta)
- **Real-time Traffic Harvesting** — Captures and processes GraphQL requests on the fly
- **Powerful Injection Rules System** — Bulk rule management (`key=value`) with instant apply/reset
- **Observed Variables Insight** — Automatically detects and ranks repeated parameters across operations
- **Inferred Schema Generation** — Builds and visualizes SDL schema with interactive graph
- **Unique "Send to Repeater"** — One-click reconstruction of full GraphQL requests with correct `doc_id`, `variables`, and `fb_api_req_friendly_name`
- **Multiple Export Formats** — JSON, CSV, and Pitchfork payloads ready for ffuf and Intruder
- **Repo & Session Management** — Persistent storage with live session view and autosave

---

## Installation

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/HasanHabeeb/HarQL
   cd HarQL
   gradle clean build

Build the extension:Bashgradle clean build
The compiled JAR will be available in build/libs/
In Burp Suite:
Go to Extensions → Installed → Add
Select the generated .jar file
Restart Burp Suite (recommended)



Usage

Load HarQL in Burp Suite
Browse the target application normally
HarQL will automatically harvest GraphQL operations from JavaScript responses and live traffic

Tabs Overview:

Observed Params — View repeated variables and send them to rules
Command Center — Manage harvested queries, variables, and injection rules
Inferred Schema — View generated SDL and interactive graph

Send to Repeater
Double-click any query → Edit variables → Click "Send to Repeater" to instantly build and send a complete, ready-to-use request.
Export Data
Use the built-in export options (JSON, CSV, Pitchfork).

Current Specialization & Roadmap

Current Version: Highly optimized for Meta platforms using their specific module patterns and Relay structure.
Upcoming Version: Will expand to support any GraphQL environment with a more generic and extensible harvesting engine.


Technical Details
HarQL uses a hybrid harvesting approach:

Static analysis of JavaScript modules (__d() pattern)
Dynamic analysis of live GraphQL traffic
In-memory storage for high performance
Advanced variable flattening and recursive rule application


License
This project is licensed under the MIT License.

Author
Hasan Habeeb
Offensive Cybersecurity Researcher
Active Meta Bug Bounty Researcher since 2021

Email: [Xvisor03@gmail.com](mailto:Xvisor03@gmail.com)  
LinkedIn: [linkedin.com/in/hasanhabeeb](https://linkedin.com/in/hasanhabeeb)  
GitHub: [github.com/Hasnhab](https://github.com/Hasnhab)


Made with passion for the bug bounty and offensive security community.
