module.exports = {
  apps: [
    {
      name: "scanlead-api",
      cwd: "/home/ubuntu/apps/scanlead/api",
      script: ".venv/bin/uvicorn",
      args: "vuln_agent.main:app --host 127.0.0.1 --port 8000",
      interpreter: "none",
      env: { PYTHONUNBUFFERED: "1" },
      max_memory_restart: "250M",
      error_file: "/home/ubuntu/apps/scanlead/logs/api.err.log",
      out_file: "/home/ubuntu/apps/scanlead/logs/api.out.log",
    },
    {
      name: "scanlead-worker",
      cwd: "/home/ubuntu/apps/scanlead/api",
      script: ".venv/bin/arq",
      args: "vuln_agent.worker.job_scan.WorkerSettings",
      interpreter: "none",
      env: { PYTHONUNBUFFERED: "1" },
      max_memory_restart: "250M",
      error_file: "/home/ubuntu/apps/scanlead/logs/worker.err.log",
      out_file: "/home/ubuntu/apps/scanlead/logs/worker.out.log",
    },
  ],
};
