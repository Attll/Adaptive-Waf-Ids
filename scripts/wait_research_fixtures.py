"""Verify host-side Redis, AMQP and SQL protocols before integration tests; no readiness by TCP alone."""
import argparse
import json
import os
import socket
import time


def probe():
    result={}
    try:
        with socket.create_connection(('127.0.0.1',int(os.environ['WAF_TEST_REDIS_PORT'])),timeout=1) as connection:
            connection.sendall(b'*1\r\n$4\r\nPING\r\n')
            if connection.recv(64)!=b'+PONG\r\n':raise RuntimeError('unexpected Redis protocol response')
        result['redis']='ready'
    except Exception as error:result['redis']=type(error).__name__
    try:
        import pika
        settings=pika.ConnectionParameters('127.0.0.1',int(os.environ['WAF_TEST_RABBIT_PORT']),socket_timeout=1,stack_timeout=2,connection_attempts=1)
        connection=pika.BlockingConnection(settings)
        connection.channel().close();connection.close()
        result['rabbitmq']='ready'
    except Exception as error:result['rabbitmq']=type(error).__name__
    try:
        import psycopg
        with psycopg.connect(host='127.0.0.1',port=int(os.environ['WAF_TEST_POSTGRES_PORT']),dbname='waf_fixture',user='waf_fixture',password='local-fixture-only',connect_timeout=1) as connection:
            assert connection.execute('select 1').fetchone()==(1,)
        result['postgresql']='ready'
    except Exception as error:result['postgresql']=type(error).__name__
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout',type=float,default=45)
    args=parser.parse_args()
    deadline=time.monotonic()+min(45,max(1,args.timeout))
    while True:
        result=probe()
        if all(value=='ready' for value in result.values()):break
        if time.monotonic()>=deadline:break
        time.sleep(.25)
    print(json.dumps(result))
    if not all(value=='ready' for value in result.values()):raise SystemExit(1)


if __name__=='__main__':main()
