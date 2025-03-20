from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# 创建一个数据库引擎（这里使用SQLite作为示例）
engine = create_engine('sqlite:///example.db')

# 创建一个基类
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    public_key = Column(String(50))
    login_time = Column(Integer)

# create a table for server's public key and private key
class ServerKey(Base):
    __tablename__ = 'server_keys'
    id = Column(Integer, primary_key=True)
    public_key = Column(String(50))
    private_key = Column(String(50))

# 创建表
Base.metadata.create_all(engine)

