import ast
import base64
import codecs
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt
from flaskProject3.config import Db_Config
from flaskProject3.model_schema import *
from flaskProject3.script_server_new import switch_task, add_task, send_command

app = Flask(__name__)
# 初始化数据库
app.config.from_object(Db_Config)
db.init_app(app)
# 解决跨域问题
CORS(app, resources={r"/api/*": {"origins": "*"}})
# 解决鉴权问题
app.config['JWT_SECRET_KEY'] = 'H3rmesk1t-d82137bf-e8c0-46a7-9cb6-d46907f33a53'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
jwt = JWTManager(app)
blacklist = set()


@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in blacklist


# 用户登录并生成Token
@app.route('/api/login', methods=['POST'])
def login():
    if request.is_json:
        username = request.json.get('username', None)
        password = request.json.get('password', None)
    else:
        username = request.form.get('username', None)
        password = request.form.get('password', None)
    password = hashlib.sha256(password.encode()).hexdigest()

    # admin/csg@admin123
    if username == 'admin' and password == 'e5186c7b475e47c00370f5188aafd03f8595fd12a75697a858ef3b956bc0046d':
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Error Username or Password..."}), 401


# 用户登出并清除Token
@app.route('/api/logout', methods=['GET'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out..."}), 200


# 定时清空blacklist
def clear_expired_tokens():
    global blacklist
    blacklist.clear()


scheduler = BackgroundScheduler()
scheduler.add_job(func=clear_expired_tokens, trigger="interval", minutes=30)
scheduler.start()


@app.route('/api/send/command', methods=['POST'])
def send_client_command():
    job_id = request.args.get('job_id')
    uuid = job_id.split("_")[0]
    command_name = job_id.split("_")[-1]
    data = request.json.get('data')
    logging.debug(f'Received job_id: {job_id}')
    print(f'Received job_id: {job_id}')
    # agent = Agent.query.filter_by(uuid=data['uuid']).first()
    try:
        send_command(uuid, command_name, data)
        logging.debug('Task sent to Kafka')
        return jsonify({'status': 'success', 'message': 'Command sent to client'}), 200
    except Exception as e:
        logging.error(f'Error sending task to Kafka: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/pause_task', methods=['POST'])
def pause_task():
    job_id = request.args.get('job_id')
    # uuid = job_id.split("_")[0]
    # task_name = job_id.split("_")[-1]
    logging.debug(f'Received job_id: {job_id}')
    print(f'Received job_id: {job_id}')
    # agent = Agent.query.filter_by(uuid=data['uuid']).first()
    try:
        switch_task(job_id, 'pause_task')
        logging.debug('Task sent to Kafka')
        return jsonify({'status': 'success', 'message': 'Task sent to client'}), 200
    except Exception as e:
        logging.error(f'Error sending task to Kafka: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/resume_task', methods=['POST'])
def resume_task():
    job_id = request.args.get('job_id')
    # uuid = job_id.split("_")[0]
    # task_name = job_id.split("_")[-1]
    logging.debug(f'Received job_id: {job_id}')
    print(f'Received job_id: {job_id}')
    # agent = Agent.query.filter_by(uuid=data['uuid']).first()
    try:
        switch_task(job_id, 'resume_task')
        logging.debug('Task sent to Kafka')
        return jsonify({'status': 'success', 'message': 'Task sent to client'}), 200
    except Exception as e:
        logging.error(f'Error sending task to Kafka: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete_task', methods=['DELETE'])
def delete_task():
    job_id = request.args.get('job_id')
    # uuid = job_id.split("_")[0]
    # task_name = job_id.split("_")[-1]
    logging.debug(f'Received job_id: {job_id}')
    print(f'Received job_id: {job_id}')
    # agent = Agent.query.filter_by(uuid=data['uuid']).first()
    try:
        switch_task(job_id, 'delete_task')
        logging.debug('Task sent to Kafka')
        return jsonify({'status': 'success', 'message': 'Task sent to client'}), 200
    except Exception as e:
        logging.error(f'Error sending task to Kafka: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/add_task', methods=['POST'])
def add_cilent_task():
    try:
        # 从POST请求的JSON数据中获取各个字段的值
        data = request.get_json()
        uuid = data.get('uuid')
        job_name = data.get('job_name')
        task_description = data.get('taskDescription', 'no')
        job_class = data.get('callTarget')
        args = data.get('args'),
        kwargs = data.get('kwargs'),
        exec_strategy = data.get('executionStrategy')
        excute_times = 0
        expression = data.get('expression', '')
        start_date = data.get('startTime')
        end_date = data.get('endTime')
        execution_time = data.get('executionTime')
        task_status = data.get('taskStatus')
        # action = data.get('action')
        action = 'add_task'
        # print(f"expression:{expression}")
        print("UUID:", uuid)
        print("Job Name:", job_name)
        print("Task Description:", task_description)
        print("Job Class:", job_class)
        print("Arguments:", args)
        print("Keyword Arguments:", kwargs)
        print("Execution Strategy:", exec_strategy)
        print("Execute Times:", excute_times)  # Always 0 as per current setup
        print("Expression:", expression)
        print("Start Date:", start_date)
        print("End Date:", end_date)
        print("Execution Time:", execution_time)
        print("Task Status:", task_status)
        print("Action:", action)

        logging.debug(f'Received data: {data}')
        add_task(uuid, job_name, task_description, job_class, args, kwargs, exec_strategy, excute_times, expression,
                 start_date, end_date, execution_time, task_status,action)
        # logging.debug('Task sent to Kafka')
        return jsonify({'status': 'success', 'message': 'Task sent to client'}), 200

    except Exception as e:
        logging.error(f'Error processing task: {str(e)}')
        return jsonify({'error': str(e)}), 500

# agent信息页面
@app.route('/api/agent/all', methods=['GET'])
@jwt_required()
def agent_query_all():
    if blacklist != None:
        for i in blacklist:
            print(i)

    res = {'status': 200, 'message': 'success'}
    try:
        page_size = int(request.args.get("page_size", default=10))
        page_number = int(request.args.get("page_number", default=1))
        agent = Agent.query.offset((page_number - 1) * page_size).limit(page_size).all()
        agent_schema = AgentSchema(many=True)
        agent_res = agent_schema.dumps(agent)
        agent_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), agent_res)
        res.update({'message': ast.literal_eval(agent_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/agent/query_uuid', methods=['GET'])
@jwt_required()
def agent_query_uuid():
    res = {'status': 200, 'message': 'success'}
    try:
        uuid = request.args.get('uuid')
        agent = Agent.query.filter_by(uuid=uuid).first()
        agent_schema = AgentSchema()
        agent_res = agent_schema.dumps(agent)
        res.update({'message': ast.literal_eval(agent_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/agent/query_ip', methods=['GET'])
@jwt_required()
def agent_query_ip():
    res = {'status': 200, 'message': 'success'}
    try:
        ip = request.args.get('ip_address')
        agent = Agent.query.filter_by(ip_address=ip).first()
        agent_schema = AgentSchema()
        agent_res = agent_schema.dumps(agent)
        res.update({'message': ast.literal_eval(agent_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/agent/delete', methods=['DELETE'])
@jwt_required()
def agent_delete_uuid():
    res = {'status': 200, 'message': 'success'}
    try:
        uuid = request.args.get('uuid')
        agent = Agent.query.filter_by(uuid=uuid).first()
        db.session.delete(agent)
        db.session.commit()
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 风险检测模块
@app.route('/api/monitored/all', methods=['GET'])
@jwt_required()
def monitored_query_files():
    res = {'status': 200, 'message': 'success'}
    try:
        page_size = int(request.args.get("page_size", default=10))
        page_number = int(request.args.get("page_number", default=1))
        monitorfiles = MonitoredFile.query.offset((page_number - 1) * page_size).limit(page_size).all()
        monitorfiles_schema = MonitorFilesSchema(many=True)
        monitorfiles_res = monitorfiles_schema.dumps(monitorfiles)
        monitorfiles_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), monitorfiles_res)
        res.update({'message': ast.literal_eval(monitorfiles_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/monitored/query_ip', methods=['GET'])
@jwt_required()
def monitored_query_files_ip():
    res = {'status': 200, 'message': 'success'}
    try:
        page_size = int(request.args.get("page_size", default=10))
        page_number = int(request.args.get("page_number", default=10))
        agentip = request.args.get("agent_ip")
        monitorfiles = MonitoredFile.query.filter_by(agentIP=agentip).offset((page_number - 1) * page_size).limit(
            page_size)
        monitorfiles_schema = MonitorFilesSchema(many=True)
        monitorfiles_res = monitorfiles_schema.dumps(monitorfiles)
        monitorfiles_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), monitorfiles_res)
        res.update({'message': ast.literal_eval(monitorfiles_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/monitored/query_uuid', methods=['GET'])
@jwt_required()
def monitored_query_files_uuid():
    res = {'status': 200, 'message': 'success'}
    try:
        page_size = int(request.args.get("page_size", default=10))
        page_number = int(request.args.get("page_number", default=10))
        uuid = request.args.get("uuid")
        monitorfiles = MonitoredFile.query.filter_by(uuid=uuid).offset((page_number - 1) * page_size).limit(page_size)
        monitorfiles_schema = MonitorFilesSchema(many=True)
        monitorfiles_res = monitorfiles_schema.dumps(monitorfiles)
        monitorfiles_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), monitorfiles_res)
        res.update({'message': ast.literal_eval(monitorfiles_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/monitored/delete', methods=['DELETE'])
@jwt_required()
def monitored_delete_ip():
    res = {'status': 200, 'message': 'success'}
    try:
        agentip = request.args.get('ip_address')
        MonitoredFile.query.filter_by(agentIP=agentip).delete()
        db.session.commit()
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/monitored/delete', methods=['DELETE'])
@jwt_required()
def monitored_delete_uuid():
    res = {'status': 200, 'message': 'success'}
    try:
        uuid = request.args.get('uuid')
        MonitoredFile.query.filter_by(uuid=uuid).delete()
        db.session.commit()
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 端口服务检测页面
@app.route('/api/hostport/query_ip', methods=['GET'])
@jwt_required()
def host_port_query_ip():
    res = {'status': 200, 'message': 'success'}
    try:
        hostip = request.args.get("host_ip")
        hostinfo = HostInfo.query.filter_by(ip=hostip)
        host_schema = HostSchema(many=True)
        porthost_res = host_schema.dumps(hostinfo)
        res.update({'message': ast.literal_eval(porthost_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/hostport/query_uuid', methods=['GET'])
@jwt_required()
def host_port_query_uuid():
    res = {'status': 200, 'message': 'success'}
    try:
        uuid = request.args.get("uuid")
        hostinfo = HostInfo.query.filter_by(uuid=uuid).first()
        host_schema = HostSchema()
        porthost_res = host_schema.dumps(hostinfo)
        res.update({'message': ast.literal_eval(porthost_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/hostport/delete', methods=['DELETE'])
@jwt_required()
def host_port_delete_ip():
    res = {'status': 200, 'message': 'success'}
    try:
        hostip = request.args.get("host_ip")
        HostInfo.query.filter_by(ip=hostip).delete()
        db.session.commit()
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/portinfo/all', methods=['GET'])
@jwt_required()
def all_port_info():
    res = {'status': 200, 'message': 'success'}
    try:
        portinfo = PortInfo.query.all()
        portinfo_schema = PortSchema(many=True)
        portdata = portinfo_schema.dumps(portinfo)
        res.update({'message': json.loads(portdata)})
        # res.update({'message': ast.literal_eval(portdata)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 进程检测页面
@app.route('/api/process/query_ip', methods=['GET'])
@jwt_required()
def process_info_query_ip():
    res = {'status': 200, 'message': 'success'}
    try:
        page_size = int(request.args.get("page_size", default=10))
        page_number = int(request.args.get("page_number", default=10))
        agentip = request.args.get("host_ip")
        processinfo = ProcessInfo.query.filter_by(agentIP=agentip).offset((page_number - 1) * page_size).limit(
            page_size)
        process_schema = ProcessSchema(many=True)
        processinfo_res = process_schema.dumps(processinfo)
        processinfo_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), processinfo_res)
        res.update({'message': ast.literal_eval(processinfo_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/process/query_uuid', methods=['GET'])
@jwt_required()
def process_info_query_uuid():
    res = {'status': 200, 'message': 'success'}
    try:
        page_size = int(request.args.get("page_size", default=10))
        page_number = int(request.args.get("page_number", default=10))
        uuid = request.args.get("uuid")
        processinfo = ProcessInfo.query.filter_by(uuid=uuid).offset((page_number - 1) * page_size).limit(page_size)
        process_schema = ProcessSchema(many=True)
        processinfo_res = process_schema.dumps(processinfo)
        processinfo_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), processinfo_res)
        res.update({'message': ast.literal_eval(processinfo_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/process/delete', methods=['DELETE'])
@jwt_required()
def process_delete_uuid():
    res = {'status': 200, 'message': 'success'}
    try:
        uuid = request.args.get('uuid')
        ProcessInfo.query.filter_by(uuid=uuid).delete()
        db.session.commit()
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/process/all', methods=['GET'])
@jwt_required()
def process_info_query_all():
    res = {'status': 200, 'message': 'success'}
    try:
        processinfo = ProcessInfo.query.all()
        process_schema = ProcessSchema(many=True)
        processinfo_res = process_schema.dumps(processinfo)
        processinfo_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), processinfo_res)
        res.update({'message': ast.literal_eval(processinfo_res)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 漏洞扫描页面
@app.route('/api/vulndetetion/query', methods=['GET'])
@jwt_required()
def vuln_detetion_query_ip():
    res = {'status': 200, 'message': 'success'}
    try:
        ip = request.args.get("host_ip")
        vulndetetion = VulDetectionResult.query.filter_by(ip=ip).first()
        vulndetetion_schema = VulDetectionSchema()
        vulndetetion_res = vulndetetion_schema.dumps(vulndetetion)
        vulndetetion_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), vulndetetion_res)
        res['message'] = ast.literal_eval(vulndetetion_res)
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/vulndetetion/query_uuid', methods=['GET'])
@jwt_required()
def vuln_detetion_query_uuid():
    res = {'status': 200, 'message': 'success'}
    try:
        uuid = request.args.get("uuid")
        vulndetetion = VulDetectionResult.query.filter_by(uuid=uuid).first()
        vulndetetion_schema = VulDetectionSchema()
        vulndetetion_res = vulndetetion_schema.dumps(vulndetetion)
        vulndetetion_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), vulndetetion_res)
        res['message'] = ast.literal_eval(vulndetetion_res)
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/vulndetetion/all', methods=['GET'])
@jwt_required()
def vuln_detetion_query_all():
    res = {'status': 200, 'message': 'success'}
    try:
        vulndetetion = VulDetectionResult.query.all()
        vulndetetion_schema = VulDetectionSchema(many=True)
        vulndetetion_res = vulndetetion_schema.dumps(vulndetetion)
        vulndetetion_res = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), vulndetetion_res)
        res['message'] = ast.literal_eval(vulndetetion_res)
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 资产测绘页面
@app.route('/api/asset_mapping/all', methods=['GET'])
@jwt_required()
def asset_mapping_query_all():
    """获取所有IP的资产测绘信息"""
    res = {'status': 200, 'message': 'success'}

    try:
        page_size = request.args.get('page_size', default=20)
        page_number = request.args.get('page_number', default=1)

        if page_size and page_number:
            page_number = max(1, int(page_number))
            page_size = max(1, int(page_size))
            assert_mapping = AssetMapping.query.offset((page_number - 1) * page_size).limit(page_size).all()
        else:
            assert_mapping = AssetMapping.query.all()

        assert_mapping_schema = AssetMappingSchema(many=True)
        data = assert_mapping_schema.dumps(assert_mapping)
        res['message'] = ast.literal_eval(data)
    except:
        res = {'status': 500, 'message': 'error'}
    return jsonify(res)


@app.route("/api/asset_mapping/query", methods=['GET'])
@jwt_required()
def asset_mapping_query_ip():
    """获取指定IP的资产测绘信息"""
    res = {'status': 200, 'message': 'success'}
    try:
        ip = request.args.get('ip')
        assert_mapping = AssetMapping.query.filter_by(ip=ip).all()
        assert_mapping_schema = AssetMappingSchema(many=True)
        data = assert_mapping_schema.dumps(assert_mapping)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route("/api/asset_mapping/delete", methods=['DELETE'])
@jwt_required()
def asset_mapping_delete_ip():
    """删除指定IP的资产测绘信息"""
    res = {'status': 200, 'message': 'success'}
    try:
        ip = request.args.get('ip')
        asset_mapping_to_delete = AssetMapping.query.filter_by(ip=ip).all()

        for entry in asset_mapping_to_delete:
            db.session.delete(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 基线检查页面
@app.route('/api/baseline_check/linux/query_ip', methods=['GET'])
@jwt_required()
def linux_security_check_query_ip():
    """获取指定IP的Linux主机基线检查信息"""
    res = {'status': 200, 'message': 'success'}

    try:
        ip = request.args.get('ip')
        linux_security_check = LinuxSecurityCheck.query.filter_by(ip=ip).all()
        linux_security_check_schema = LinuxSecurityCheckSchema(many=True)
        data = linux_security_check_schema.dumps(linux_security_check)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/baseline_check/linux/query_uuid', methods=['GET'])
@jwt_required()
def linux_security_check_query_uuid():
    """获取指定IP的Linux主机基线检查信息"""
    res = {'status': 200, 'message': 'success'}

    try:
        uuid = request.args.get('uuid')
        linux_security_check = LinuxSecurityCheck.query.filter_by(uuid=uuid).all()
        linux_security_check_schema = LinuxSecurityCheckSchema(many=True)
        data = linux_security_check_schema.dumps(linux_security_check)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route("/api/baseline_check/linux/delete", methods=['DELETE'])
@jwt_required()
def linux_security_check_delete():
    """删除指定IP的Linux主机基线检查信息"""
    res = {'status': 200, 'message': 'success'}
    try:
        uuid = request.args.get('uuid')
        linux_security_check_to_delete = LinuxSecurityCheck.query.filter_by(uuid=uuid).all()
        for entry in linux_security_check_to_delete:
            db.session.delete(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/baseline_check/windows/query_ip', methods=['GET'])
@jwt_required()
def windows_security_check_query_ip():
    """获取指定IP的Windows主机基线检查信息"""
    res = {'status': 200, 'message': 'success'}

    try:
        ip = request.args.get('ip')
        windows_security_check = WindowsSecurityCheck.query.filter_by(ip=ip).all()
        windows_security_check_schema = WindowsSecurityCheckSchema(many=True)
        data = windows_security_check_schema.dumps(windows_security_check)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/baseline_check/windows/query_uuid', methods=['GET'])
@jwt_required()
def windows_security_check_query_uuid():
    """获取指定IP的Windows主机基线检查信息"""
    res = {'status': 200, 'message': 'success'}

    try:
        uuid = request.args.get('uuid')
        windows_security_check = WindowsSecurityCheck.query.filter_by(uuid=uuid).all()
        windows_security_check_schema = WindowsSecurityCheckSchema(many=True)
        data = windows_security_check_schema.dumps(windows_security_check)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route("/api/baseline_check/windows/delete", methods=['DELETE'])
@jwt_required()
def windows_security_check_delete():
    """删除指定IP的Windows主机基线检查信息"""
    res = {'status': 200, 'message': 'success'}
    try:
        uuid = request.args.get('uuid')
        windows_security_check_to_delete = WindowsSecurityCheck.query.filter_by(uuid=uuid).all()
        for entry in windows_security_check_to_delete:
            db.session.delete(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/baseline_check/linux/all', methods=['GET'])
@jwt_required()
def linux_security_check_all():
    """获取指定IP的Linux主机基线检查信息"""
    res = {'status': 200, 'message': 'success'}

    try:
        linux_security_check = LinuxSecurityCheck.query.all()
        linux_security_check_schema = LinuxSecurityCheckSchema(many=True)
        data = linux_security_check_schema.dumps(linux_security_check)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/baseline_check/windows/all', methods=['GET'])
@jwt_required()
def windows_security_check_all():
    """获取指定IP的Windows主机基线检查信息"""
    res = {'status': 200, 'message': 'success'}

    try:
        windows_security_check = WindowsSecurityCheck.query.all()
        windows_security_check_schema = WindowsSecurityCheckSchema(many=True)
        data = windows_security_check_schema.dumps(windows_security_check)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 文件监控页面
@app.route('/api/FileIntegrityInfo/query_uuid', methods=['GET'])
@jwt_required()
def FileIntegrityInfo_query_uuid():
    res = {'status': 200, 'message': 'success'}
    alerts = []
    result_dict = {}
    try:
        uuid = request.args.get('uuid')
        result = FileInfo.query.filter_by(uuid=uuid)
        for fileinfo in result:
            md5 = fileinfo.filename_md5
            record_data = {
                'filename': fileinfo.filename,
                'file_content_md5': fileinfo.file_content_md5,
                'ctime': fileinfo.ctime,
                'mtime': fileinfo.mtime,
                'atime': fileinfo.atime,
                'host_IP': fileinfo.host_IP,
                'host_name': fileinfo.host_name,
                'is_exists': fileinfo.is_exists,
                'event_time': fileinfo.event_time}

            if md5 in result_dict:
                result_dict[md5].append(record_data)
            else:
                result_dict[md5] = [record_data]
            # 设置告警状态
        for md5, records in result_dict.items():
            for record in records:
                filename = record["filename"].split(",")[-1]
                event_time = record["event_time"].split(",")[-1]
                hostname = record["host_name"].split(",")[-1]
                hostIP = record["host_IP"].split(",")[-1]
                # 上面是前端展示的告警信息
                md5_set = record["file_content_md5"].split(",")
                atimes = record["atime"].split(",")
                ctimes = record["ctime"].split(",")
                mtimes = record["mtime"].split(",")
                is_exists = record["is_exists"].split(",")
                if (len(set(md5_set)) != 1):  # 判断修改状态
                    alert_type = "modified"
                elif (((ctimes)) == ((mtimes)) and len(set(atimes)) == 1):  # 判断创建状态,之前判断状态有误，a=c=m 导致created的也是normal。
                    alert_type = "created"
                elif (int(is_exists[-1]) != 1):
                    alert_type = "deleted"
                else:
                    alert_type = "normal"
                items = dict(filename=filename, hostIP=hostIP, event_time=event_time, alert_type=alert_type,
                             hostname=hostname)
                alerts.append(items)
                res.update({'message': alerts})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)

@app.route('/api/FileIntegrityInfo/query_ip', methods=['GET'])
@jwt_required()
def FileIntegrityInfo_query_ip():
    res = {'status': 200, 'message': 'success'}
    alerts = []
    result_dict = {}
    try:
        hostip = request.args.get('hostip')
        result = FileInfo.query.filter_by(host_IP=hostip)
        for fileinfo in result:
            md5 = fileinfo.filename_md5
            record_data = {
                'filename': fileinfo.filename,
                'file_content_md5': fileinfo.file_content_md5,
                'ctime': fileinfo.ctime,
                'mtime': fileinfo.mtime,
                'atime': fileinfo.atime,
                'host_IP': fileinfo.host_IP,
                'host_name': fileinfo.host_name,
                'is_exists': fileinfo.is_exists,
                'event_time': fileinfo.event_time}

            if md5 in result_dict:
                result_dict[md5].append(record_data)
            else:
                result_dict[md5] = [record_data]
            # 设置告警状态
        for md5, records in result_dict.items():
            for record in records:
                filename = record["filename"].split(",")[-1]
                event_time = record["event_time"].split(",")[-1]
                hostname = record["host_name"].split(",")[-1]
                hostIP = record["host_IP"].split(",")[-1]
                # 上面是前端展示的告警信息
                md5_set = record["file_content_md5"].split(",")
                atimes = record["atime"].split(",")
                ctimes = record["ctime"].split(",")
                mtimes = record["mtime"].split(",")
                is_exists = record["is_exists"].split(",")
                if (len(set(md5_set)) != 1):  # 判断修改状态
                    alert_type = "modified"
                elif (((ctimes)) == ((mtimes)) and len(set(atimes)) == 1):  # 判断创建状态,之前判断状态有误，a=c=m 导致created的也是normal。
                    alert_type = "created"
                elif (int(is_exists[-1]) != 1):
                    alert_type = "deleted"
                else:
                    alert_type = "normal"
                items = dict(filename=filename, hostIP=hostIP, event_time=event_time, alert_type=alert_type,
                             hostname=hostname)
                alerts.append(items)
                res.update({'message': alerts})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)

@app.route('/api/FileIntegrityInfo/query_time', methods=['GET'])
@jwt_required()
def FileIntegrityInfo_query_time():
    res = {'status': 200, 'message': 'success'}
    alerts = []
    result_dict = {}
    try:
        start_time = float(request.args.get('start_time'))
        end_time = float(request.args.get('end_time'))
        result = FileInfo.query.filter(FileInfo.event_time.between(start_time, end_time)).all()
        for fileinfo in result:
            md5 = fileinfo.filename_md5
            record_data = {
                'filename': fileinfo.filename,
                'file_content_md5': fileinfo.file_content_md5,
                'ctime': fileinfo.ctime,
                'mtime': fileinfo.mtime,
                'atime': fileinfo.atime,
                'host_IP': fileinfo.host_IP,
                'host_name': fileinfo.host_name,
                'is_exists': fileinfo.is_exists,
                'event_time': fileinfo.event_time}
            if md5 in result_dict:
                result_dict[md5].append(record_data)
            else:
                result_dict[md5] = [record_data]
            # 设置告警状态
        for md5, records in result_dict.items():
            for record in records:
                filename = record["filename"].split(",")[-1]
                event_time = record["event_time"].split(",")[-1]
                hostname = record["host_name"].split(",")[-1]
                hostIP = record["host_IP"].split(",")[-1]
                # 上面是前端展示的告警信息
                md5_set = record["file_content_md5"].split(",")
                atimes = record["atime"].split(",")
                ctimes = record["ctime"].split(",")
                mtimes = record["mtime"].split(",")
                is_exists = record["is_exists"].split(",")
                if (len(set(md5_set)) != 1):  # 判断修改状态
                    alert_type = "modified"
                elif (((ctimes)) == ((mtimes)) and len(set(atimes)) == 1):  # 判断创建状态,之前判断状态有误，a=c=m 导致created的也是normal。
                    alert_type = "created"
                elif (int(is_exists[-1]) != 1):
                    alert_type = "deleted"
                else:
                    alert_type = "normal"
                items = dict(filename=filename, hostIP=hostIP, event_time=event_time, alert_type=alert_type,
                             hostname=hostname)
                alerts.append(items)
                res.update({'message': alerts})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)

@app.route('/api/FileIntegrityInfo/all', methods=['GET'])
@jwt_required()
def FileIntegrityInfo_all():
    res = {'status': 200, 'message': 'success'}
    alerts = []
    result_dict = {}
    try:
        result = FileInfo.query.all()
        for fileinfo in result:
            md5 = fileinfo.filename_md5
            record_data = {
                'id': fileinfo.id,
                'uuid': fileinfo.uuid,
                'filename': fileinfo.filename,
                'file_content_md5': fileinfo.file_content_md5,
                'ctime': fileinfo.ctime,
                'mtime': fileinfo.mtime,
                'atime': fileinfo.atime,
                'host_IP': fileinfo.host_IP,
                'host_name': fileinfo.host_name,
                'is_exists': fileinfo.is_exists,
                'event_time': fileinfo.event_time
            }
            if md5 in result_dict:
                result_dict[md5].append(record_data)
            else:
                result_dict[md5] = [record_data]
            # 设置告警状态
        for md5, records in result_dict.items():
            for record in records:
                id = record["id"]
                uuid = record["uuid"].split(",")[-1]
                filename = record["filename"].split(",")[-1]
                event_time = record["event_time"].split(",")[-1]
                hostname = record["host_name"].split(",")[-1]
                hostIP = record["host_IP"].split(",")[-1]
                # 上面是前端展示的告警信息
                md5_set = record["file_content_md5"].split(",")
                atimes = record["atime"].split(",")
                ctimes = record["ctime"].split(",")
                mtimes = record["mtime"].split(",")
                is_exists = record["is_exists"].split(",")
                if (len(set(md5_set)) != 1):  # 判断修改状态
                    alert_type = "modified"
                elif (((ctimes)) == ((mtimes)) and len(set(atimes)) == 1):  # 判断创建状态,之前判断状态有误，a=c=m 导致created的也是normal。
                    alert_type = "created"
                elif (int(is_exists[-1]) != 1):
                    alert_type = "deleted"
                else:
                    alert_type = "normal"
                items = dict(id=id, uuid=uuid, filename=filename, hostIP=hostIP, event_time=event_time,
                             alert_type=alert_type,
                             hostname=hostname)
                alerts.append(items)
                res.update({'message': alerts})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 蜜罐页面
@app.route('/api/honeypot/all', methods=['GET'])
@jwt_required()
def honey_pot_all():
    res = {'status': 200, 'message': 'success'}

    try:
        honey_pots = HoneyPot.query.all()
        honey_pot_schema = HoneyPotSchema(many=True)
        data = honey_pot_schema.dumps(honey_pots)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/honeypot/query_atkip', methods=['GET'])
@jwt_required()
def honey_pot_query_atkip():
    res = {'status': 200, 'message': 'success'}

    try:
        ip = request.args.get('atkip')
        honey_pots = HoneyPot.query.filter_by(atk_ip=ip).all()
        honey_pot_schema = HoneyPotSchema(many=True)
        data = honey_pot_schema.dumps(honey_pots)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/honeypot/query_uuid', methods=['GET'])
@jwt_required()
def honey_pot_query_uuid():
    res = {'status': 200, 'message': 'success'}

    try:
        uuid = request.args.get('uuid')
        honey_pots = HoneyPot.query.filter_by(uuid=uuid).first()
        honey_pot_schema = HoneyPotSchema()
        data = honey_pot_schema.dumps(honey_pots)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# flask内存马检测
@app.route('/api/memoryshell/check', methods=['POST'])
@jwt_required()
def memory_shell_check():
    res = {'status': 200, 'message': 'failed'}
    try:
        data = request.form.get('data')
        poc = base64.b64decode(data).decode()
        # poc = decode_unicode_string(poc)
        # poc = decode_hex_string(poc)
        # poc = remove_splice(poc)
        s, flag = detect_flask_shell(poc, keywords)
        if flag:
            memshell = MemoryShell(shell_data=data, shell_poc=s, is_shell=flag, detect_time=datetime.now())
            db.session.add(memshell)
            db.session.commit()
            res.update({'message': {'shell_data': data, 'shell_poc': s, 'is_shell': flag}})
        else:
            res.update({'message': {'is_shell': flag}})
    except Exception as e:
        print(str(e))
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/memoryshell/all', methods=['GET'])
@jwt_required()
def memory_shell_all():
    res = {'status': 200, 'message': 'success'}
    try:
        memory_shells = MemoryShell.query.all()
        memory_shell_schema = MemoryShellSchema(many=True)
        data = memory_shell_schema.dumps(memory_shells)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/memoryshell/query_id', methods=['GET'])
@jwt_required()
def memory_shell_query_id():
    res = {'status': 200, 'message': 'success'}
    try:
        id = request.args.get('id')
        memory_shells = MemoryShell.query.filter_by(id=id).all()
        memory_shell_schema = MemoryShellSchema(many=True)
        data = memory_shell_schema.dumps(memory_shells)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/taskdetail/all', methods=['GET'])
@jwt_required()
def taskdetail_query_all():
    res = {'status': 200, 'message': 'success'}
    try:
        page_size = int(request.args.get("page_size", default=10))
        page_number = int(request.args.get("page_number", default=1))
        task = TaskDetail.query.offset((page_number - 1) * page_size).limit(page_size).all()
        task_schema = TaskDetailSchema(many=True)
        task_res = task_schema.dumps(task)
        # res.update({'message': ast.literal_eval(task_res)})
        # 使用json.loads来转换JSON字符串为Python字典
        task_res = json.loads(task_res)
        # 将所有日期转换为UNIX时间戳
        for item in task_res:
            for key in ['create_time', 'start_time', 'end_time', 'start_timestamp', 'update_timestamp']:  # 假设的日期字段
                if item[key]:
                    # 将ISO格式的日期字符串转换为datetime对象，然后转换为时间戳
                    dt = datetime.fromisoformat(item[key].replace('Z', '+00:00'))
                    item[key] = int(dt.timestamp())
        res.update({'message': task_res})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route("/api/brute-force/all", methods=["GET"])
@jwt_required()
def brute_force_all():
    # 查询暴力破解已经狩猎到的ip
    res = {'status': 200, 'message': 'success'}

    try:
        brute_force = BruteForceRecord.query.all()
        brute_schema = BruteForceRecordSchema(many=True)
        data = brute_schema.dumps(brute_force)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
        # res.update({'message': data})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/brute-force/query_agent', methods=['GET'])
@jwt_required()
def brute_force_query_agent():
    res = {'status': 200, 'message': 'success'}

    try:
        agent_ip = request.args.get('agent')
        brute_force = BruteForceRecord.query.filter_by(agent_ip=agent_ip).all()
        brute_schema = BruteForceRecordSchema(many=True)
        data = brute_schema.dumps(brute_force)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
        # res.update({'message': data})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route("/api/privilege-escalation/all", methods=["GET"])
@jwt_required()
def privilege_escalation_all():
    # 查询权限提升已经狩猎到的ip
    res = {'status': 200, 'message': 'success'}

    try:
        privilege_escalation = PrivilegeEscalation.query.all()
        privilege_escalation_schema = PrivilegeEscalationSchema(many=True)
        data = privilege_escalation_schema.dumps(privilege_escalation)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
        # res.update({'message': data})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/privilege-escalation/query_agent', methods=['GET'])
@jwt_required()
def privilege_escalation_query_agent():
    res = {'status': 200, 'message': 'success'}

    try:
        agent_ip = request.args.get('agent')
        privilege_escalation = PrivilegeEscalation.query.filter_by(agent_ip=agent_ip).all()
        privilege_escalation_schema = PrivilegeEscalationSchema(many=True)
        data = privilege_escalation_schema.dumps(privilege_escalation)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
        # res.update({'message': data})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route("/api/defense-avoidance/all", methods=["GET"])
@jwt_required()
def defense_avoidance_all():
    # 查询防御规避已经狩猎到的ip
    res = {'status': 200, 'message': 'success'}

    try:
        defense_avoidance = DefenseAvoidance.query.all()
        defense_avoidance_schema = DefenseAvoidanceSchema(many=True)
        data = defense_avoidance_schema.dumps(defense_avoidance)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
        # res.update({'message': data})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


@app.route('/api/defence-avoidance/query_agent', methods=['GET'])
@jwt_required()
def defence_avoidance_query_agent():
    res = {'status': 200, 'message': 'success'}

    try:
        agent_ip = request.args.get('agent')
        defense_avoidance = DefenseAvoidance.query.filter_by(agent_ip=agent_ip).all()
        defense_avoidance_schema = DefenseAvoidanceSchema(many=True)
        data = defense_avoidance_schema.dumps(defense_avoidance)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
        # res.update({'message': data})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)

# 查询所有加密文件
@app.route("/api/isolate/all", methods=["GET"])
@jwt_required()
def isolate_all():
    res = {'status': 200, 'message': 'success'}
    try:
        isolate_files = MicroIsolate.query.all()
        isolate_schema = MicroIsolateSchema(many=True)
        data = isolate_schema.dumps(isolate_files)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
        # res.update({'message': data})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)


# 查询指定Agent的加密文件
@app.route('/api/isolate/query_agent', methods=['GET'])
@jwt_required()
def isolate_query_agent():
    res = {'status': 200, 'message': 'success'}

    try:
        agent_ip = request.args.get('agent')
        isolate_files = MicroIsolate.query.filter_by(agent_ip=agent_ip).all()
        isolate_schema = MicroIsolateSchema(many=True)
        data = isolate_schema.dumps(isolate_files)
        data = re.sub(date_pattern, lambda x: str(convert_to_timestamp(x.group())), data)
        res.update({'message': ast.literal_eval(data)})
        # res.update({'message': data})
    except Exception as e:
        res = {'status': 500, 'message': str(e)}
    return jsonify(res)

# 内存马检测部分
keywords = {
    "app.add_url_rule": 10,
    "_request_ctx_stack": 5,
    "current_app": 5,
    "request.args.get": 3,
    "request.args.post": 3,
    "__getitem__": 2,
    "__globals__": 2,
    "os": 2,
    "popen": 2,
    "eval": 2,
    "attr": 2,
    "__subclasses__": 1,
    "__builtins__": 1,
    "__class__": 1,
    "__bases__": 1,
    "base64": 1,
    "chr": 1,
}


def decode_unicode_string(s):
    pattern = re.compile(r'\\u[0-9a-fA-F]{4}')
    matches = pattern.findall(s)
    for match in matches:
        decoded = codecs.decode(match, 'unicode_escape')
        s = s.replace(match, decoded)
    return s


def decode_hex_string(s):
    pattern = re.compile(r'\\x[0-9a-fA-F]{2}')
    matches = pattern.findall(s)
    for match in matches:
        decoded = bytes.fromhex(match[2:]).decode('utf-8')
        s = s.replace(match, decoded)
    return s


def remove_splice(s):
    s = s.replace('"+"', "")
    s = s.replace('\'+\'', "")
    return s


def detect_flask_shell(s, keywords):
    score_base = sum(keywords.values())
    score = 0
    for keyword, keyword_score in keywords.items():
        if keyword in s:
            score += keyword_score

    if score / score_base > 0.5:
        return s, True
    return s, False


# 时间戳转换
# 正则表达式，用于匹配特定格式的日期
date_pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'


# 函数，将日期字符串转换为Unix时间戳
def convert_to_timestamp(date_str):
    # 移除'T'字符，以匹配格式 '%Y-%m-%d %H:%M:%S'
    date_str_formatted = date_str.replace('T', ' ')
    # 转换为datetime对象
    date_obj = datetime.strptime(date_str_formatted, '%Y-%m-%d %H:%M:%S')
    # 转换为Unix时间戳
    return int(date_obj.timestamp())


if __name__ == '__main__':
    app.config['JSON_AS_ASCII'] = False
    app.run(debug=True, port=5000)
