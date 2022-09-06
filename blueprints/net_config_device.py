from flask import Blueprint, render_template, request, redirect
from flask_login import login_required
from models import ConfigDevices, ConfigDevicesLog
from exts import db_mysql, fernet
from netmiko import ConnectHandler
import concurrent.futures
import time


bp = Blueprint("config_devices", __name__, url_prefix="/config_devices")


def config_dev(dev_ip, dev_name, dev_password, dev_vendor, dev_port, command, operation_ip):
    operation_result = ''
    try:
        if dev_vendor.lower() == 'huawei':
            sw = {'device_type': 'huawei',
                  'ip': dev_ip,
                  'username': dev_name,
                  'password': dev_password,
                  'port': dev_port}

            connect = ConnectHandler(**sw)
            huawei_output = connect.send_config_set(command)
            huawei_result = (f'----华为 {dev_ip} 上的运行结果----\n ' + huawei_output)
            operation_result = huawei_result
            connect.disconnect()

        elif dev_vendor.lower() == 'h3c':
            sw = {'device_type': 'hp_comware',
                  'ip': dev_ip,
                  'username': dev_name,
                  'password': dev_password,
                  'port': dev_port}

            connect = ConnectHandler(**sw)
            h3c_output = connect.send_config_set(command)
            h3c_result = (f'----H3C {dev_ip} 上的运行结果----\n ' + h3c_output)
            operation_result = h3c_result
            connect.disconnect()

        elif dev_vendor.lower() == 'cisco':
            sw = {'device_type': 'cisco_ios',
                  'ip': dev_ip,
                  'username': dev_name,
                  'password': dev_password,
                  'port': dev_port}
            connect = ConnectHandler(**sw)
            cisco_output = connect.send_config_set(command)
            cisco_result = (f'----Cisco {dev_ip} 上的运行结果----\n ' + cisco_output)
            operation_result = cisco_result
            connect.disconnect()
        logs = ConfigDevicesLog(target=dev_ip, remote_ip_addr=operation_ip, action='Configure', status='Success',
                                time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), messages='No Error')

        return {'operation_log_information': operation_result,
                'writer_log': logs}

    except Exception as e:
        logs = ConfigDevicesLog(target=dev_ip, remote_ip_addr=operation_ip, action='Configure', status='Error',
                                time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), messages=e)
        return {'operation_log_information': str(e),
                'writer_log': logs}


@bp.route("/info")
@login_required
def config_devices():
    all_device = ConfigDevices.query.all()
    context = {'all_device': all_device}
    return render_template("config_devices.html", **context)


@bp.route("/add", methods=['GET', 'POST'])
@login_required
def config_devices_add():
    vendor_choices = ["huawei", "h3c", "cisco"]
    context = {'vendor_choices': vendor_choices}
    if request.method == "GET":
        return render_template("config_devices_add.html", **context)

    elif request.method == "POST":
        ip = request.form.get("ip")
        dev_name = request.form.get("dev_name")
        username = request.form.get("username")
        password = fernet.encrypt(request.form.get("password").encode())
        dev_port = request.form.get("dev_port")
        vendor = request.form.get("vendor")

        device_1 = ConfigDevices(ip_address=ip, hostname=dev_name, username=username, password=password, ssh_port=dev_port,
                                 vendor=vendor)
        db_mysql.session.add(device_1)
        db_mysql.session.commit()
        return redirect('info')


@bp.route("/edit", methods=['GET', 'POST'])
@login_required
def config_devices_edit():
    devices_id = request.args.get("device_id")
    dev_id = ConfigDevices.query.filter_by(id=devices_id)[0]
    if request.method == "GET":
        vendor_choices = ["huawei", "h3c", "cisco"]
        context = {'dev_id': dev_id,
                   'vendor_choices': vendor_choices}
        return render_template("config_devices_edit.html", **context)

    elif request.method == "POST":
        dev_id.ip_address = request.form.get("ip")
        dev_id.hostname = request.form.get("dev_name")
        dev_id.username = request.form.get("username")
        if request.form.get("password"):
            dev_id.password = fernet.encrypt(request.form.get("password").encode())
        dev_id.ssh_port = request.form.get("dev_port")
        dev_id.vendor = request.form.get("vendor")
        db_mysql.session.commit()
        return redirect("info")


@bp.route("/delete", methods=['GET'])
@login_required
def config_devices_delete():
    if request.method == "GET":
        devices_id = request.args.get("device_id")
        print(devices_id)
        ConfigDevices.query.filter_by(id=devices_id).delete()
        db_mysql.session.commit()
        return redirect('info')


@bp.route("/config", methods=['GET', 'POST'])
@login_required
def config_devices_config():
    dev_information = list()
    web_operation_log = list()
    if request.method == "GET":
        all_device = ConfigDevices.query.all()
        context = {'all_device': all_device}
        return render_template("config_devices_config.html", **context)

    elif request.method == "POST":
        remote_ip = str(request.remote_addr)
        start_time = time.time()
        dev_list = list()
        selected_device_id = request.form.getlist("device")
        # 获取WEB页面上的命令信息
        get_huawei_command = request.form.get('huawei_command').splitlines()
        get_h3c_command = request.form.get('h3c_command').splitlines()
        get_cisco_command = request.form.get('cisco_command').splitlines()

        if selected_device_id:
            for one_device_id in selected_device_id:
                dev = ConfigDevices.query.filter_by(id=int(one_device_id))[0]
                if dev.vendor.lower() == 'huawei':
                    dev_list.append([dev.ip_address, dev.username, fernet.decrypt(dev.password.encode()), dev.vendor,
                                     dev.ssh_port, get_huawei_command, remote_ip])

                elif dev.vendor.lower() == 'h3c':
                    dev_list.append([dev.ip_address, dev.username, fernet.decrypt(dev.password.encode()), dev.vendor,
                                     dev.ssh_port, get_h3c_command, remote_ip])

                elif dev.vendor.lower() == 'cisco':
                    dev_list.append([dev.ip_address, dev.username, fernet.decrypt(dev.password.encode()), dev.vendor,
                                     dev.ssh_port, get_cisco_command, remote_ip])

            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [executor.submit(config_dev, param[0], param[1], param[2], param[3], param[4], param[5],
                                           param[6]) for param in dev_list]
                return_value = [f.result() for f in futures]
                for one_return_value in return_value:
                    dev_information.append(one_return_value['operation_log_information'])
                    web_operation_log.append(one_return_value['writer_log'])

            dev_information.append(f'----执行时长为 {time.time() - start_time} ----\n')

            for one_web_operation_log in web_operation_log:
                db_mysql.session.add(one_web_operation_log)
                db_mysql.session.commit()

            context = {'result': '\n'.join(dev_information)}
            return render_template('config_devices_verify_config.html', **context)

        else:
            context = {'result': '请先选择需要配置的设备'}
            return render_template('config_devices_verify_config.html', **context)


@bp.route("/log")
def config_devices_log():
    page = request.args.get("page", 1)
    log_all = ConfigDevicesLog.query.paginate(page=int(page), per_page=13)
    context = {'log_all': log_all}
    return render_template("config_devices_config_log.html", **context)
