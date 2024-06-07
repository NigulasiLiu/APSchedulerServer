from datetime import datetime
from typing import Any

import pymysql
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class MySQLManage:
    """
    MySQL 数据库管理器
    """
    #db: pymysql.connections.Connection = None
    def __init__(self, host, user, password, db, port=3306):
        self.host = host
        self.user = user
        self.password = password
        self.db = db
        self.port = port
        self.engine = self.get_engine()
        self.Session = sessionmaker(bind=self.engine)

    def close_all_sessions(self):
        self.engine.dispose()  # 关闭 engine 和其维护的所有连接
    def get_engine(self):
        """
        Create and return the SQLAlchemy engine instance.
        """
        connection_string = f"mysql+pymysql://{self.user}:{self.password}@{self.host}:{self.port}/{self.db}?charset=utf8"
        engine = create_engine(connection_string, echo=False, pool_size=10, max_overflow=20, pool_pre_ping=True)
        Base.metadata.create_all(engine)  # Ensure all tables are created based on ORM definitions
        return engine

    def create_data(self, model_instance):
        """
        使用 session 插入新记录。
        """
        session = self.Session()
        try:
            session.add(model_instance)
            session.commit()
            print("数据插入成功")
        except SQLAlchemyError as e:
            session.rollback()
            print(f"数据插入失败: {e}")
        finally:
            session.close()

    def get_data(self, model_class, **kwargs):
        """
        使用 ORM model 和 filter 条件来获取单条数据。
        """
        session = self.Session()
        try:
            result = session.query(model_class).filter_by(**kwargs).first()
            return result
        finally:
            session.close()

    def update_data(self, model_class, conditions, update_data):
        """
        使用 session 更新记录。
        """
        session = self.Session()
        try:
            obj = session.query(model_class).filter_by(**conditions).first()
            if obj:
                for key, value in update_data.items():
                    setattr(obj, key, value)
                session.commit()
                print("数据更新成功")
        except SQLAlchemyError as e:
            session.rollback()
            print(f"数据更新失败: {e}")
        finally:
            session.close()

    def delete_data(self, model_class, **conditions):
        """
        使用 session 删除记录。
        """
        session = self.Session()
        try:
            objs = session.query(model_class).filter_by(**conditions)
            objs.delete()
            session.commit()
            print("数据删除成功")
        except SQLAlchemyError as e:
            session.rollback()
            print(f"数据删除失败: {e}")
        finally:
            session.close()

    def update_all_data(self, model_class, update_data):
        """
        使用 session 更新所有记录的特定字段。
        """
        session = self.Session()
        try:
            # 更新所有记录
            session.query(model_class).update(update_data)
            session.commit()
            print("所有数据更新成功")
        except SQLAlchemyError as e:
            session.rollback()
            print(f"数据更新失败: {e}")
        finally:
            session.close()

    def delete_all_data(self, model_class):
        """
        使用 session 删除所有记录。
        """
        session = self.Session()
        try:
            # 删除所有记录
            session.query(model_class).delete()
            session.commit()
            print("所有数据删除成功")
        except SQLAlchemyError as e:
            session.rollback()
            print(f"数据删除失败: {e}")
        finally:
            session.close()
