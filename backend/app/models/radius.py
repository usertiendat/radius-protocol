"""
SQLAlchemy ORM Models cho 9 bảng chuẩn FreeRADIUS 3.x.
Tất cả các model ở đây đều chỉ ánh xạ dữ liệu (Read/Write thuần túy),
hoàn toàn không chứa Foreign Key vật lý và không thực hiện thao tác DDL.
"""

from sqlalchemy import BigInteger, Column, DateTime, Integer, String
from app.database import Base


class Nas(Base):
    """
    Bảng nas: Danh sách các thiết bị Network Access Server và Shared Secret.
    """
    __tablename__ = "nas"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    nasname = Column(String(128), nullable=False, index=True)
    shortname = Column(String(32), nullable=True)
    type = Column(String(30), nullable=True, default="other")
    ports = Column(Integer, nullable=True)
    secret = Column(String(60), nullable=False)
    server = Column(String(64), nullable=True)
    community = Column(String(50), nullable=True)
    description = Column(String(200), nullable=True, default="RADIUS Client")


class NasReload(Base):
    """
    Bảng nasreload: Lưu timestamp yêu cầu nạp lại cấu hình client cho NAS.
    """
    __tablename__ = "nasreload"
    __table_args__ = {"extend_existing": True}

    nasipaddress = Column(String(15), primary_key=True)
    reloadtime = Column(DateTime, nullable=False)


class RadAcct(Base):
    """
    Bảng radacct: Lưu nhật ký các phiên truy cập mạng do FreeRADIUS tự động ghi qua UDP 1813.
    Dữ liệu lịch sử bất biến; FastAPI chỉ đọc, tuyệt đối không UPDATE/DELETE.
    """
    __tablename__ = "radacct"
    __table_args__ = {"extend_existing": True}

    radacctid = Column(BigInteger, primary_key=True, autoincrement=True)
    acctsessionid = Column(String(64), nullable=False, default="", index=True)
    acctuniqueid = Column(String(32), nullable=False, default="", unique=True, index=True)
    username = Column(String(64), nullable=False, default="", index=True)
    realm = Column(String(64), nullable=True, default="")
    nasipaddress = Column(String(15), nullable=False, default="", index=True)
    nasportid = Column(String(32), nullable=True)
    nasporttype = Column(String(32), nullable=True)
    acctstarttime = Column(DateTime, nullable=True, index=True)
    acctupdatetime = Column(DateTime, nullable=True)
    acctstoptime = Column(DateTime, nullable=True, index=True)
    acctinterval = Column(Integer, nullable=True)
    acctsessiontime = Column(Integer, nullable=True)
    acctauthentic = Column(String(32), nullable=True)
    connectinfo_start = Column(String(128), nullable=True)
    connectinfo_stop = Column(String(128), nullable=True)
    acctinputoctets = Column(BigInteger, nullable=True)
    acctoutputoctets = Column(BigInteger, nullable=True)
    calledstationid = Column(String(50), nullable=False, default="")
    callingstationid = Column(String(50), nullable=False, default="")
    acctterminatecause = Column(String(32), nullable=False, default="")
    servicetype = Column(String(32), nullable=True)
    framedprotocol = Column(String(32), nullable=True)
    framedipaddress = Column(String(15), nullable=False, default="")
    framedipv6address = Column(String(45), nullable=False, default="")
    framedipv6prefix = Column(String(45), nullable=False, default="")
    framedinterfaceid = Column(String(44), nullable=False, default="")
    delegatedipv6prefix = Column(String(45), nullable=False, default="")
    # 'class' là từ khóa trong Python, ánh xạ qua tên cột 'class'
    class_ = Column("class", String(64), nullable=True)


class RadCheck(Base):
    """
    Bảng radcheck: Lưu thông tin điều kiện xác thực của người dùng mạng.
    Lưu ý: Mật khẩu mạng của FreeRADIUS PAP lưu ở thuộc tính Cleartext-Password trong bảng này.
    """
    __tablename__ = "radcheck"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, default="", index=True)
    attribute = Column(String(64), nullable=False, default="")
    op = Column(String(2), nullable=False, default=":=")
    value = Column(String(253), nullable=False, default="")


class RadGroupCheck(Base):
    """
    Bảng radgroupcheck: Điều kiện kiểm tra áp dụng theo nhóm người dùng.
    """
    __tablename__ = "radgroupcheck"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    groupname = Column(String(64), nullable=False, default="", index=True)
    attribute = Column(String(64), nullable=False, default="")
    op = Column(String(2), nullable=False, default=":=")
    value = Column(String(253), nullable=False, default="")


class RadGroupReply(Base):
    """
    Bảng radgroupreply: Thuộc tính trả về cho NAS áp dụng theo nhóm (VLAN ID, Filter-Id).
    """
    __tablename__ = "radgroupreply"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    groupname = Column(String(64), nullable=False, default="", index=True)
    attribute = Column(String(64), nullable=False, default="")
    op = Column(String(2), nullable=False, default="=")
    value = Column(String(253), nullable=False, default="")


class RadPostAuth(Base):
    """
    Bảng radpostauth: Lịch sử các lần xác thực Access-Accept và Access-Reject.
    Lưu ý an ninh: Cột pass_ không bao giờ được trả về qua API.
    """
    __tablename__ = "radpostauth"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, default="", index=True)
    pass_ = Column("pass", String(64), nullable=False, default="")
    reply = Column(String(32), nullable=False, default="")
    authdate = Column(DateTime, nullable=False, index=True)
    class_ = Column("class", String(64), nullable=True)


class RadReply(Base):
    """
    Bảng radreply: Thuộc tính trả về cho NAS cấu hình riêng theo từng cá nhân người dùng.
    """
    __tablename__ = "radreply"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, default="", index=True)
    attribute = Column(String(64), nullable=False, default="")
    op = Column(String(2), nullable=False, default="=")
    value = Column(String(253), nullable=False, default="")


class RadUserGroup(Base):
    """
    Bảng radusergroup: Ánh xạ người dùng vào một hoặc nhiều nhóm mạng.
    """
    __tablename__ = "radusergroup"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, default="", index=True)
    groupname = Column(String(64), nullable=False, default="")
    priority = Column(Integer, nullable=False, default=1)
