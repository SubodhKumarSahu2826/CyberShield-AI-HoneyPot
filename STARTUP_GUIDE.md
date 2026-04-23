# CyberShield Platform: Startup & Teardown Guide

This guide provides step-by-step instructions on how to start the CyberShield AI-Adaptive Honeypot platform from a completely offline state, and how to safely tear it down when finished.

## 🟡 Prerequisites (Manual Initialization)
Before securely booting the containerized platform, ensure that your local AI provider (Ollama) is active. The AI classifier and response generator nodes strictly rely on this to function.

1. **Launch the Ollama App:** 
   * Open Ollama from your Mac Applications folder. You should see the Ollama icon actively running in your Mac menu bar at the top right.
2. **Ensure the Target LLM is Available in Memory:**
   * Open a new local terminal and run:
     ```bash
     ollama run qwen2.5:3b
     ```
   * *Wait until it initializes and you see the `>>>` prompt.* 
   * Type `/bye` to exit. This ensures the model is active in local GPU/RAM memory, preventing timeout failures during your first attack simulation.

---

## 🟢 Step 1: Spin up the Docker Infrastructure
The entire backend ecosystem (Database, Honeypot Core, Classifiers, Data Dashboard) is containerized and orchestrated via Docker Compose.

1. **Open a Terminal** and navigate to your honeypot project folder:
   ```bash
   cd "/Users/sks/Desktop/AI-Adaptive Cyber HoneyPot"
   ```

2. **Start the Docker Network:**
   * Run the following command. The `-d` flag runs them in detached mode (in the background) so you can continue using your terminal.
   ```bash
   docker compose up -d
   ```
   > [!TIP]
   > If you make any Python or configuration changes to the system while it is offline, you must replace the above command with `docker compose up -d --build` to force a clean recompile of your code changes into the containers.

3. **Verify the Stack:**
   * Wait 10-15 seconds for the database and APIs to initialize.
   * Run `docker ps` to ensure all 6 containers are **Up** and show **Healthy**:
     * `honeypot-dashboard` (Port 3000)
     * `honeypot-capture` (Port 8080)
     * `honeypot-api` 
     * `honeypot-classifier`
     * `honeypot-postgres`
     * `honeypot-response-generator`

---

## 🔵 Step 2: Access the User Interfaces
Once Docker confirms everything is actively running, your frontend applications are ready to be used.

**1. The Logistics Website (Vulnerable Target):**
* Locate the `index.html` file inside your project folder (`/Users/sks/Desktop/AI-Adaptive Cyber HoneyPot/`).
* Simply double-click it (or drag it into your browser) to open it. 
* This is your attacker simulation interface where you will launch payloads (e.g., Track Shipment feedback, Custom API request).

**2. The Threat Intelligence Dashboard (Security Center):**
* Open your browser and navigate to: http://localhost:3000
* This responsive dashboard automatically polls data securely from the `honeypot-dashboard` container, dynamically populating threat intelligence in real-time.

---

## 🔴 Step 3: Shutting It Down Completely
When you are completely done testing the platform and want to tear the system down to save locally allocated RAM and CPU:

1. Close your browser tabs for the Dashboard and Logistics website.
2. In your terminal inside the project directory, run:
   ```bash
   docker compose down
   ```
   > [!NOTE]  
   > This command safely stops and removes the active containers and network bridges. However, your PostgreSQL database volumes and safely captured attack histories are entirely persisted locally!
3. You can now cleanly "Quit" the Ollama app from your Mac menu bar. 

*Your environment is now completely safely shut down.*
