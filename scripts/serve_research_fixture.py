"""Owned loopback stack for browser QA. STOP file shuts down every owned process."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
from threading import Thread
import time
from scripts.benchmark_gateway_research import java_service, free_port, wait_http


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("new fixture output directory required")
    for key in ("WAF_TEST_REDIS_PORT","WAF_TEST_RABBIT_PORT","WAF_TEST_POSTGRES_PORT"):
        if not os.environ.get(key,"").isdigit():
            parser.error("isolated dependency ports required")
    args.output.mkdir(parents=True)
    root=Path(__file__).resolve().parents[1]
    token=secrets.token_urlsafe(32)
    os.environ["WAF_INTERNAL_TOKEN"]=token
    import uvicorn
    with ExitStack() as cleanup:
        environment={"WAF_INTERNAL_TOKEN":token,"REDIS_HOST":"127.0.0.1","REDIS_PORT":os.environ["WAF_TEST_REDIS_PORT"],
            "RABBITMQ_HOST":"127.0.0.1","RABBITMQ_PORT":os.environ["WAF_TEST_RABBIT_PORT"],
            "WAF_POSTGRES_URL":f"jdbc:postgresql://127.0.0.1:{os.environ['WAF_TEST_POSTGRES_PORT']}/waf_fixture",
            "WAF_POSTGRES_EXTERNAL_URL":f"jdbc:postgresql://127.0.0.1:{os.environ['WAF_TEST_POSTGRES_PORT']}/waf_fixture",
            "WAF_POSTGRES_USER":"waf_fixture","WAF_POSTGRES_PASSWORD":"local-fixture-only",
            "WAF_ADMIN_USERNAME":"fixture-admin","WAF_ADMIN_INITIAL_PASSWORD":"local-fixture-only",
            "ADAPTIVE_WAF_CONTROL_ESCALATION_AUTO_BLOCK_ON_REVISION":"false"}
        control,_=java_service(root,"security-control-service",environment,args.output,cleanup)
        backend,_=java_service(root,"demo-backend",environment,args.output,cleanup)
        def api(application):
            listener=cleanup.enter_context(socket.socket())
            listener.bind(("127.0.0.1",0))
            url=f"http://127.0.0.1:{listener.getsockname()[1]}"
            server=uvicorn.Server(uvicorn.Config(application,access_log=False,log_level="error"))
            thread=Thread(target=lambda:server.run(sockets=[listener]),daemon=True)
            thread.start()
            def stop():
                server.should_exit=True
                thread.join(timeout=5)
            cleanup.callback(stop)
            wait_http(url+"/health")
            return url
        from adaptive_waf.service.app import create_app
        from adaptive_waf.runtime.artifacts import load_adaptive_pipeline
        from adaptive_waf.service.escalation import DisabledEscalationWorker
        detection=api(create_app(pipeline_loader=lambda:load_adaptive_pipeline(strategy="guarded_fixed"),escalation_worker=DisabledEscalationWorker()))
        from adaptive_waf.network_sensor.service import create_app as sensor_app,SensorSettings
        sensor=api(sensor_app(SensorSettings(redis_port=int(os.environ["WAF_TEST_REDIS_PORT"]))))
        from adaptive_waf.adaptation.service import create_app as adaptation_app,AdaptationSettings
        adaptation=api(adaptation_app(AdaptationSettings(control_service_url=control,curated_root=args.output/"curated")))
        environment.update(CONTROL_SERVICE_URL=control,DETECTION_SERVICE_URL=detection,DEMO_BACKEND_URL=backend)
        gateway,_=java_service(root,"gateway-service",environment,args.output,cleanup)
        dashboard_port=free_port()
        vite_env={**os.environ,"VITE_CONTROL_SERVICE_URL":control,"VITE_GATEWAY_URL":gateway,
                  "VITE_DETECTION_SERVICE_URL":detection,"VITE_NETWORK_SENSOR_URL":sensor,"VITE_ADAPTATION_SERVICE_URL":adaptation}
        log=cleanup.enter_context((args.output/"dashboard.log").open("w"))
        process=subprocess.Popen(["node",str(root/"dashboard/node_modules/vite/bin/vite.js"),"--host","127.0.0.1","--port",str(dashboard_port)],
            cwd=root/"dashboard",env=vite_env,stdout=log,stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
        def stop_vite():
            process.terminate()
            process.wait(timeout=5)
        cleanup.callback(stop_vite)
        dashboard=f"http://127.0.0.1:{dashboard_port}"
        wait_http(dashboard,process)
        (args.output/"urls.json").write_text(json.dumps({"dashboard":dashboard,"control":control,"gateway":gateway,
            "detection":detection,"sensor":sensor,"adaptation":adaptation,"scope":"owned loopback fixture"},indent=2))
        print("Fixture ready:",dashboard,flush=True)
        while not (args.output/"STOP").exists():
            time.sleep(.2)


if __name__=="__main__":
    main()
