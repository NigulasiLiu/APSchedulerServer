from datetime import datetime
from threading import Thread

from kafka import KafkaConsumer, KafkaProducer
import json

from flaskProject3.models import Agent, MonitoredFile, ProcessInfo, HostInfo, PortInfo, VulDetectionResult, VulDetectionResultBugPoc, \
    VulDetectionResultBugExp, VulDetectionResultFinger
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from owltask.taskmain import ScheduledTask

app = Flask(__name__)

# Kafka 消费者配置
consumer_config = {
    'bootstrap_servers': 'localhost:9092',
    'group_id': 'sys_resource_group',
    'auto_offset_reset': 'earliest',
    'value_deserializer': lambda x: json.loads(x.decode('utf-8'))
}
# Kafka 生产者配置
producer_config = {
    'bootstrap_servers': 'localhost:9092',  # 例如：'localhost:9092'
    'value_serializer': lambda v: json.dumps(v).encode('utf-8')
}

# 配置数据库连接字符串
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:4372978@localhost:3306/hids'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 禁止追踪修改，减少内存占用

# 创建数据库实例
db = SQLAlchemy(app)

mainscheduledtask = ScheduledTask()
mainscheduledtask.run()


# 配置topic
# sys_resource_topic = 'sys_resource_topic'
# os_info_topic = 'os_info_topic'
# file_monitor_topic = 'file_monitor_topic'
# ps_monitor_topic = 'ps_monitor_topic'
# nmap_scan_topic = 'nmap_scan_topic'
# vuln_scan_topic = 'vuln_scan_topic'
# pause_task_topic = 'pause_task_topic'
# topics=[sys_resource_topic, os_info_topic,file_monitor_topic,ps_monitor_topic,nmap_scan_topic,vuln_scan_topic,pause_task_topic]

# server端发送命令
def send_command(uuid, command, data):
    producer = KafkaProducer(**producer_config)
    message = {
        "uuid": uuid,
        "msg_type": "json",
        "msg_body": {
            "command": command,
            "data": data
        }
    }

    topic_name = "command_topic"

    producer.send(topic_name, value=message)
    producer.close()

    return "send command successfully"


# job_id包含了uuid以及job_name
def switch_task(job_id, action):
    message = {
        'action': action,
        'msg_body': {
            'job_id': job_id,
        }
    }
    # mainscheduledtask = ScheduledTask()
    mainscheduledtask.parse_message(message)
    return "send command successfully"


def add_task(uuid, job_name, task_description, job_class, args, kwargs, exec_strategy, excute_times, expression,
             start_date, end_date, execution_time, task_status, action):
    message = {
        'action': action,
        'msg_body': {
            'job_id': f"{uuid}_{job_name}",
            'job_name': job_name,
            'taskDescription': task_description,
            'job_class': job_class,
            'args': args,
            'kwargs': kwargs,
            'exec_strategy': exec_strategy,
            'excute_times': excute_times,
            'expression': expression,
            'start_date': start_date,
            'end_date': end_date,
            'executionTime': execution_time,
            'taskStatus': task_status
        }
    }

    print("解析message:")
    for key, value in message['msg_body'].items():
        print(f"{key}: {value}")

    mainscheduledtask.parse_message(message)

    return "send command successfully"


# server端接收消息
def server_consumer_worker(topic):
    with app.app_context():
        consumer = KafkaConsumer(topic, **consumer_config)
        for message in consumer:
            # 在这里处理消息，可以调用其他函数处理消息
            print(f"Thread {topic}: Received message:", message.value)
            if message.value['msg_body']['data'] is not None:
                messagestr = message.value
                if topic == "sys_resource_topic":
                    # 对数据进行解析存储到数据库
                    process_message_sys(messagestr)
                elif topic == "os_info_topic":
                    process_message_os(messagestr)
                elif topic == "file_monitor_topic":
                    process_message_file(messagestr)
                elif topic == "ps_monitor_topic":
                    process_message_ps(messagestr)
                elif topic == "nmap_scan_topic":
                    process_message_nmap(messagestr)
                elif topic == "vuln_scan_topic":
                    process_message_vuln(messagestr)

        consumer.close()


def start_server_consumers(topics):
    threads = []
    for topic in topics:
        t = Thread(target=server_consumer_worker, args=(topic,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()


def process_message_os(data):
    try:
        os_info_data = data['msg_body']['data']
        host_name = os_info_data['os_name']
        ip_address = os_info_data['ip_address']
        os_version_ver = os_info_data['os_version']['os_version']
        py_version = os_info_data['py_version']
        processor_name = os_info_data['processor_name']
        processor_architecture = os_info_data['processor_architecture']

        agent_info = Agent(
            host_name=host_name,
            ip_address=ip_address,
            os_version=os_version_ver,
            py_version=py_version,
            processor_name=processor_name,
            processor_architecture=processor_architecture
        )

        db.session.add(agent_info)
        db.session.commit()

        print("Data stored successfully.")
    except Exception as e:
        print(f"Error processing message: {e}")


def process_message_sys(data):
    try:
        sys_data = data['msg_body']['data']
        disk_total = sys_data['disk']
        mem_total = sys_data['mem_total']
        mem_use = sys_data['mem_use']
        cpu_use = sys_data['cpu_use']

        agent_info = Agent(
            disk_total=disk_total,
            mem_total=mem_total,
            mem_use=mem_use,
            cpu_use=cpu_use
        )

        db.session.add(agent_info)
        db.session.commit()

        print("Data stored successfully.")
    except Exception as e:
        print(f"Error processing message: {e}")


def process_message_ps(data):
    try:
        ps_info_data = data['msg_body']['data']

        new_process = ProcessInfo(
            pid=ps_info_data['pid'],
            name=ps_info_data['name'],
            username=ps_info_data['username'],
            cpu_percent=ps_info_data['cpu_percent'],
            memory_percent=ps_info_data['memory_percent'],
            highRisk=ps_info_data['highRisk']
        )
        db.session.add(new_process)
        db.session.commit()
        return 'Process saved successfully!', 201
    except Exception as e:
        print(f"Error processing message: {e}")


def process_message_nmap(data):
    try:
        data = data['msg_body']['data']
        for item in data:
            host = HostInfo(
                ipv4=item['ipv4'],
                vendor=item.get('vendor', ''),
                state=item.get('state', ''),
                uuid=item['uuid']
            )
            db.session.add(host)
            db.session.commit()

            if 'tcp' in item:
                for port_number, port_data in item['tcp'].items():
                    port = PortInfo(
                        host_id=host.id,
                        port_number=port_number,
                        state=port_data.get('state', ''),
                        name=port_data.get('name', ''),
                        product=port_data.get('product', ''),
                        version=port_data.get('version', ''),
                        extrainfo=port_data.get('extrainfo', '')
                    )
                    db.session.add(port)
                    db.session.commit()

        return 'Data saved successfully!', 201
    except Exception as e:
        print(f"Error processing message: {e}")


def process_message_file(data):
    try:
        file_info_data = data['msg_body']['data']
        agentIP = file_info_data['agentIP']
        file_path = file_info_data['file_path']
        change_type = file_info_data['change_type']
        file_type = file_info_data['file_type']
        timestamp = file_info_data['timestamp']
        uuid = file_info_data['uuid']

        file_info = MonitoredFile(
            agentIP=agentIP,
            file_type=file_type,
            change_type=change_type,
            timestamp=timestamp,
            uuid=uuid
        )

        db.session.add(file_info)
        db.session.commit()

        print("Process info stored successfully.")
    except Exception as e:
        print(f"Error processing message: {e}")


def process_message_vuln(data):
    try:
        data = data['msg_body']['data']
        for item in data:
            ip = item['ip']
            uuid = item['uuid']
            scan_time = datetime.now()

            # Insert into 'vul_detection_result' table
            for open_port in item['openport']:
                vul_detection_result = VulDetectionResult(ip=ip, uuid=uuid, scanTime=scan_time, port=open_port['port'])
                db.session.add(vul_detection_result)
                db.session.commit()

            # Insert into 'vul_detection_result_bug_exp' table
            for bug_exp in item['bugexp']:
                bug_ip = bug_exp['ip']
                bug_exp_value = bug_exp['exp']
                bug_exp_row = VulDetectionResultBugExp(ip=bug_ip, bug_exp=bug_exp_value, uuid=uuid, scanTime=scan_time)
                db.session.add(bug_exp_row)
                db.session.commit()

            # Insert into 'vul_detection_result_bug_poc' table
            for bug_poc in item['bugpoc']:
                poc_url = bug_poc['url']
                poc_value = bug_poc['poc']
                bug_poc_row = VulDetectionResultBugPoc(ip=ip, url=poc_url, bug_poc=poc_value, uuid=uuid,
                                                       scanTime=scan_time)
                db.session.add(bug_poc_row)
                db.session.commit()

            # Insert into 'vul_detection_result_finger' table
            for finger in item['fingerout']:
                finger_url = finger['url']
                finger_value = finger['finger']
                finger_row = VulDetectionResultFinger(ip=ip, url=finger_url, finger=finger_value, uuid=uuid,
                                                      scanTime=scan_time)
                db.session.add(finger_row)
                db.session.commit()

        db.session.close()

        print("Bug Exp List info stored successfully.")
    except Exception as e:
        print(f"Error processing message: {e}")

# 测试
# send_command("sys_resource")
# send_command("os_info")
# time.sleep(8)
# start_server_consumers(topics)
