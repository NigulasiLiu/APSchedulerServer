import atexit
import datetime
from enum import Enum
from random import random

import pytz

from owltask.core.scheduler import Scheduler
from owltask.appconfig.settings import SCHEDULER_TASK, KAFKA_TOPIC, KAFKA_BROKER_URL, TASKS_ROOT
from owltask.core.logger import logger
from owltask.core.mysql import get_database as get_mysql
from flaskProject3.models import TaskDetail


class ScheduledTask:
    TASK_DIR = TASKS_ROOT

    class JobExecStrategy(Enum):
        interval = "interval"
        date = "date"
        cron = "cron"
        once = "once"

    def __init__(self):
        self.scheduler = None
        self.rd = None
        self.mysql = None

    def parse_message(self, message):
        """
        处理接收到的消息并根据消息内容添加定时任务
        :param message: 接收到的消息字典
        """
        if message.get("action") == "run_immediately":
            self.run_job_once(message['msg_body'].get("job_class"))
        elif message.get("action") == "delete_task":
            self.delete_job(message['msg_body'].get("job_id"))
        elif message.get("action") == "pause_task":
            self.pause_job(message['msg_body'].get("job_id"))
        elif message.get("action") == "resume_task":
            self.restart_job(message['msg_body'].get("job_id"))
        else:#创建新任务
            shanghai_tz = pytz.timezone("Asia/Shanghai")

            print("尝试添加任务详情")
            # print("job_id:", message['msg_body'].get("job_id"))
            # print("job_class:", message['msg_body'].get("job_class"))
            # print("exec_strategy:", message['msg_body'].get("exec_strategy"))
            # print("expression:", message['msg_body'].get("expression"))
            # print("excute_times:", message['msg_body'].get("excute_times"))
            # print("start_date:", message['msg_body'].get("start_date"))
            # print("end_date:", message['msg_body'].get("end_date"))
            # print("taskDescription:", message['msg_body'].get("taskDescription"))
            # print("taskStatus:", message['msg_body'].get("taskStatus"))
            try:

                exec_strategy = message['msg_body'].get("exec_strategy")
                job_params = {
                    "job_id": message['msg_body'].get("job_id"),
                    "job_class": message['msg_body'].get("job_class"),
                    "args": message['msg_body'].get("args"),
                    "kwargs": message['msg_body'].get("kwargs"),
                }
                task_detail = TaskDetail(
                    job_id=message['msg_body'].get("job_id"),
                    job_class=message['msg_body'].get("job_class"),
                    exec_strategy=message['msg_body'].get("exec_strategy"),
                    expression=message['msg_body'].get("expression"),
                    excute_times=message['msg_body'].get("excute_times"),
                    create_time=datetime.datetime.now(shanghai_tz),
                    start_time=message['msg_body'].get("start_date"),
                    end_time=message['msg_body'].get("end_date"),
                    taskDescription=message['msg_body'].get("taskDescription"),
                    exception="-",
                    retval="等待调度",
                    start_timestamp=None,
                    update_timestamp=None,
                    process_time=0,
                    status="waiting" if message['msg_body'].get("taskStatus") == "normal" else "pending"
                )
                self.create_job(task_detail)

                # 为不同的任务类型构建触发器并添加任务
                if exec_strategy == self.JobExecStrategy.cron.value:
                    job_params["expression"] = message['msg_body'].get("expression")
                    job_params["start_date"] = message['msg_body'].get("start_date")
                    job_params["end_date"] = message['msg_body'].get("end_date")
                    job_params["timezone"] = message['msg_body'].get("timezone")
                    self.scheduler.add_cron_job(**job_params)
                    print("添加Cron任务成功")
                elif exec_strategy == self.JobExecStrategy.interval.value:
                    job_params["expression"] = message['msg_body'].get("expression")
                    job_params["start_date"] = message['msg_body'].get("start_date")
                    job_params["end_date"] = message['msg_body'].get("end_date")
                    job_params["timezone"] = message['msg_body'].get("timezone")
                    job_params["jitter"] = message['msg_body'].get("jitter", None)
                    print("开始添加Interval任务")
                    self.scheduler.add_interval_job(**job_params)
                    print("添加Interval任务成功")
                elif exec_strategy == self.JobExecStrategy.date.value:
                    job_params["expression"] = message['msg_body'].get("executionTime")
                    print("开始添加Date任务")
                    self.scheduler.add_date_job(**job_params)
                    print("添加Date任务成功")
                elif exec_strategy == self.JobExecStrategy.once.value:
                    print("添加once任务成功")
                    # 这种方式会自动执行事件监听器，用于保存执行任务完成后的日志
                    job_params["job_id"] = f"-{random.randint(1000, 9999)}" + job_params["job_id"]
                    self.scheduler.add_date_job(**job_params, expression=datetime.datetime.now())
                else:
                    raise ValueError("Unsupported execution strategy: {}".format(exec_strategy))

            except Exception as e:
                logger.error(f"Failed to process message: {str(e)}")
                print(f"处理消息失败: {str(e)}")

    def create_job(self, model_instance) -> None:
        """
        使用调度器判断任务是否存在，如果存在，那么无论是旧任务还是刚刚创建的新任务，都直接覆盖旧任务信息，否则任务信息的更新将由 on_job_removed 来完成
        """
        try:
            print(f":添加新任务{model_instance.job_id}")
            job_id = model_instance.job_id
            task = self.scheduler.has_job_by_jobid(job_id)
            if task:
                task_exist = self.mysql.get_data(TaskDetail,job_id=job_id);
                if(task_exist):
                    # self.mysql.put_data(TaskDetail, {"job_id": job_id}, model_instance)
                    print(f"已有相同名称的定时任务，不再添加{job_id}")
                else:
                    self.mysql.create_data(model_instance)
            else:
                print(f"调度器添加任务失败，不添加新任务{job_id}")
        except Exception as e:
            logger.error("创建任务:" + model_instance.job_id + " 时发生错误: {e}")
            model_instance.exception = str(e)
            self.mysql.create_data(model_instance)

    def run_job_once(self, job_class: str) -> None:
        """
        只运行一次任务，适用于“立刻扫描”等功能
        """
        try:
            self.scheduler.run_job_once()
        except Exception as e:
            print(f"单次运行任务 {job_class} 时发生错误: {e}")
            logger.error(f"单次运行任务 {job_class} 时发生错误: {e}")

    def delete_job(self, job_id: str) -> None:
        """
        使用调度器方法先将任务删除，任务信息的更新将由 on_job_removed 来完成
        """
        try:
            task = self.scheduler.has_job_by_jobid(job_id)
            if task:
                # self.mysql.delete_data(TaskDetail, job_id=job_id)
                # print(f"成功删除job_id为 {job_id} 的任务")
                self.scheduler.remove_job_by_jobid(job_id)
            else:
                print(f"不存在job_id为 {job_id} 的任务,不需要删除")
        except Exception as e:
            print(f"删除任务 {job_id} 时发生错误: {e}")
            logger.error(f"删除任务 {job_id} 时发生错误: {e}")

    def pause_job(self, job_id: str) -> None:
        """
        使用调度器方法先将任务暂停，任务信息的更新将由 on_job_modified 来完成
        """
        try:
            task = self.scheduler.has_job_by_jobid(job_id)
            if task:
                self.scheduler.pause_job_by_jobid(job_id)
            else:
                print(f"不存在job_id为 {job_id} 的任务，无需暂停")
        except Exception as e:
            print(f"暂停任务 {job_id} 时发生错误: {e}")
            logger.error(f"暂停任务 {job_id} 时发生错误: {e}")

    def restart_job(self, job_id: str) -> None:
        """
        使用调度器方法先将任务恢复执行，任务信息的更新将由 on_job_modified 来完成
        """
        try:
            task = self.scheduler.has_job_by_jobid(job_id)
            if task:
                self.scheduler.resume_job_by_jobid(job_id)
            else:
                print(f"不存在job_id为 {job_id} 的任务，无法恢复执行")
        except Exception as e:
            print(f"恢复任务 {job_id} 时发生错误: {e}")
            logger.error(f"恢复任务 {job_id} 时发生错误: {e}")

    def run(self) -> None:
        """
        启动监听订阅消息（阻塞）
        :return:
        """
        self.start_mysql()
        self.start_scheduler()

    def start_mysql(self) -> None:
        """
        启动 mysql
        :return:
        """
        self.mysql = get_mysql()
        if self.mysql:
            print("mysql 启动成功")
        # self.mysql.connect_to_database()#MYSQL_DB_HOST, MYSQL_DB_USER, MYSQL_DB_PASSWORD, MYSQL_DB_NAME, MYSQL_DB_PORT

    def start_scheduler(self) -> None:
        """
        启动定时任务
        :return:
        """
        self.scheduler = Scheduler()
        self.scheduler.start()
        print("Scheduler 启动成功")

    # def start_kafka(self) -> None:
    #     """
    #     启动 Kafka 消费者，监听并处理消息
    #     """
    #     consumer = KafkaConsumer(
    #         KAFKA_TOPIC,
    #         bootstrap_servers=KAFKA_BROKER_URL,
    #         group_id='task_processing_group',  # 所有处理任务的消费者共享同一个 group_id
    #         auto_offset_reset='latest',  # 从最新的消息开始读取
    #         value_deserializer=lambda m: json.loads(m.decode('utf-8')),
    #     )
    #
    #     logger.info("已成功启动程序，等待接收消息...")
    #     print("已成功启动程序，等待接收消息...")
    #
    #     try:
    #         for message in consumer:
    #             data = message.value
    #             self.parse_message(data)
    #     except KeyboardInterrupt:
    #         print("程序终止")
    #     finally:
    #         consumer.close()

    def close(self) -> None:
        """
        # pycharm 执行停止，该函数无法正常被执行，怀疑是因为阻塞导致或 pycharm 的强制退出导致
        # 报错导致得退出，会被执行
        关闭程序
        :return:
        """
        self.scheduler.shutdown()
        # self.mysql.close_database_connection()
        # if self.scheduler:
        #     self.scheduler.shutdown()
        # if self.rd:
        #     self.rd.close_database_connection()



if __name__ == '__main__':
    # agent_uuid = '6543210000'
    main = ScheduledTask()
    atexit.register(main.close)
    main.run()
