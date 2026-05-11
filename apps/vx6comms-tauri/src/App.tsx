import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";

export default function App() {
  const [nodeName, setNodeName] = useState("alice");
  const [status, setStatus] = useState("idle");
  const [output, setOutput] = useState("");
  const [peerAddr, setPeerAddr] = useState("[::1]:4242");
  const [serviceName, setServiceName] = useState("web");
  const [serviceTarget, setServiceTarget] = useState("127.0.0.1:8080");
  const [connectService, setConnectService] = useState("alice.web");
  const [connectListen, setConnectListen] = useState("127.0.0.1:9000");

  async function runStatus() {
    setStatus("checking status...");
    try {
      const out = await invoke<string>("vx6_status");
      setOutput(out);
      setStatus("status received");
    } catch (err) {
      setStatus("status failed");
      setOutput(String(err));
    }
  }

  async function initNode() {
    setStatus("initializing...");
    try {
      const out = await invoke<string>("vx6_init", { name: nodeName });
      setOutput(out);
      setStatus("initialized");
    } catch (err) {
      setStatus("init failed");
      setOutput(String(err));
    }
  }

  async function startNode() {
    setStatus("starting node...");
    try {
      const out = await invoke<string>("vx6_node_start");
      setOutput(out);
      setStatus("node command issued");
    } catch (err) {
      setStatus("start failed");
      setOutput(String(err));
    }
  }

  async function stopNode() {
    setStatus("stopping node...");
    try {
      const out = await invoke<string>("vx6_node_stop");
      setOutput(out);
      setStatus("node stopped");
    } catch (err) {
      setStatus("stop failed");
      setOutput(String(err));
    }
  }

  async function exec(args: string[], label: string) {
    setStatus(label);
    try {
      const out = await invoke<string>("vx6_exec", { args });
      setOutput(out);
      setStatus(`${label} complete`);
    } catch (err) {
      setStatus(`${label} failed`);
      setOutput(String(err));
    }
  }

  return (
    <main className="app">
      <header className="top">
        <h1>VX6 MeshChat</h1>
        <p>Desktop control app over VX6 protocol runtime</p>
      </header>

      <div className="grid">
        <section className="card">
          <h2>Node</h2>
          <label htmlFor="name">Node name</label>
          <input
            id="name"
            value={nodeName}
            onChange={(e) => setNodeName(e.target.value)}
            placeholder="node name"
          />
          <label htmlFor="peer">Initial peer</label>
          <input
            id="peer"
            value={peerAddr}
            onChange={(e) => setPeerAddr(e.target.value)}
            placeholder="[ipv6]:port"
          />
          <div className="row">
            <button onClick={() => exec(["init", "--name", nodeName, "--listen", "[::]:4242", "--peer", peerAddr], "init")}>Init</button>
            <button onClick={startNode}>Start Node</button>
            <button className="ghost" onClick={stopNode}>Stop Node</button>
          </div>
          <div className="row">
            <button className="ghost" onClick={runStatus}>Status</button>
            <button className="ghost" onClick={() => exec(["identity"], "identity")}>Identity</button>
            <button className="ghost" onClick={() => exec(["peer"], "peer list")}>Peers</button>
          </div>
        </section>

        <section className="card">
          <h2>Services</h2>
          <label htmlFor="svcname">Service name</label>
          <input
            id="svcname"
            value={serviceName}
            onChange={(e) => setServiceName(e.target.value)}
            placeholder="web"
          />
          <label htmlFor="svctarget">Target</label>
          <input
            id="svctarget"
            value={serviceTarget}
            onChange={(e) => setServiceTarget(e.target.value)}
            placeholder="127.0.0.1:8080"
          />
          <div className="row">
            <button onClick={() => exec(["service", "add", "--name", serviceName, "--target", serviceTarget], "service add")}>Add</button>
            <button onClick={() => exec(["service", "remove", "--name", serviceName], "service remove")}>Remove</button>
            <button className="ghost" onClick={() => exec(["reload"], "reload")}>Reload</button>
            <button className="ghost" onClick={() => exec(["service"], "service list")}>List</button>
          </div>
        </section>

        <section className="card">
          <h2>Connect</h2>
          <label htmlFor="connectsvc">Remote service</label>
          <input
            id="connectsvc"
            value={connectService}
            onChange={(e) => setConnectService(e.target.value)}
            placeholder="alice.web"
          />
          <label htmlFor="connectlisten">Local listen</label>
          <input
            id="connectlisten"
            value={connectListen}
            onChange={(e) => setConnectListen(e.target.value)}
            placeholder="127.0.0.1:9000"
          />
          <div className="row">
            <button onClick={() => exec(["connect", "--service", connectService, "--listen", connectListen], "connect")}>Connect</button>
            <button className="ghost" onClick={() => exec(["debug", "dht-status"], "dht status")}>DHT</button>
            <button className="ghost" onClick={() => exec(["list"], "list")}>Directory</button>
          </div>
        </section>
      </div>

      <section className="card">
        <h2>Runtime Output</h2>
        <p className="status">{status}</p>
        <pre>{output || "No output yet"}</pre>
      </section>
    </main>
  );
}
