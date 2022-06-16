import traceback
import xlrd
import logging
import json
import requests
import argparse

import requests.packages.urllib3

requests.packages.urllib3.disable_warnings()


def get_logger(log_file_name, filemode='w'):
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s] [line:%(lineno)d] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=log_file_name,
        filemode=filemode
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger("MyLogger").addHandler(console)
    return logging.getLogger("MyLogger")


logger = get_logger(".\\daut.log")


############################################################################################
def normalize(attr_name, val):  # convert into target type like str or int
    value = val
    try:
        if attr_name in ("networkId", "devId", "cpmPolicyId"):
            value = int(val)
        elif attr_name in ("cusAttrs.sysSshPort", "cusAttrs.sysRdpPort", "cusAttrs.sysDbPort"):
            value = str(int(val))
        elif attr_name in ["status", "cpmDisabled"]:
            value = True if val is not None and val == "true" else False
    except ValueError:
        value = "__INVALID__"
    return value


# read data from device.xls
def read_dev_data_from_file(file_path, sheet_name):
    try:
        data = xlrd.open_workbook(file_path)
        table = data.sheet_by_name(sheet_name)
        devlist = []
        col_dict = {}
        for i in range(0, table.ncols):
            col_dict[i] = table.cell_value(0, i)

        for i in range(1, table.nrows):
            dev_dict = {}
            for j in range(0, table.ncols):
                attr_name = col_dict[j]
                if table.cell_value(i, j) != "":
                    dev_dict[attr_name] = normalize(attr_name, table.cell_value(i, j))
                else:
                    continue
            devlist.append(dev_dict)
        return devlist
    except Exception as e:
        logger.exception(e)


#######################################################################
class PAM:
    username = ""
    password = ""
    pvwa = ""
    token = ""
    headers = None
    devType = {}

    def __init__(self, address, username, password):
        self.pvwa = "https://" + address
        self.username = username
        self.password = password
        url = self.pvwa + "/api/auth/logon"
        payload = json.dumps({"username": username, "password": password})
        headers = {"Content-Type": "application/json"}
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        self.token = json.loads(response.text)['token']

        self.headers = {
            "Authorization": self.token,
            "Content-Type": "application/json"
        }
        self.devType = self.get_device_type()

    def transform(self, device):
        result = {}
        for key in device.keys():
            if key == "devType":
                result["devTypeId"] = self.devType[device["devType"]]
            elif key == "devType":
                continue
            elif "assAttrs." in key or "cusAttrs." in key:
                key1 = key.split(".")[0]
                key2 = key.split(".")[1]
                if result.get(key1, None) is None:
                    result[key1] = {}
                result[key1][key2] = device[key]
            else:
                result[key] = device[key]
        return result

    def add_device(self, device):
        url = self.pvwa + "/api/device"
        device = self.transform(device)
        payload = json.dumps(device)
        response = requests.request("POST", url, headers=self.headers, data=payload, verify=False)
        if response.status_code != 200:
            raise Exception(response.text)
        if "id" not in json.loads(response.text).keys():
            raise Exception(response.text)

    def get_device_Id(self, devname):
        url = self.pvwa + "/api/device?filter=name eq " + devname
        response = requests.request("GET", url, headers=self.headers, verify=False)
        if response.status_code != 200:
            raise Exception(response.text)
        else:
            num_of_total_devices = json.loads(response.text)["totalElements"]
            if num_of_total_devices == 0:
                print("Could not find the device name = " + devname)
                raise Exception("Could not find the device name = " + devname)
            else:
                device = json.loads(response.text)["content"][0]
                return device["id"]
        return 0

    def trigger_cpm_task(self, accId, action):
        if action not in ["verify", "change", "reconcile"]:
            raise Exception(
                "Trigger CPM Task Error: [{0}] is not expected. The action shall be in ['verify', 'change', 'reconcile']".format(
                    action))
        url = self.pvwa + "/api/account/{0}/action/{1}".format(accId, action)
        data = json.dumps({})

        response = requests.request("POST", url, headers=self.headers, data=data, verify=False)
        if response.status_code != 200:
            raise Exception(response.text)

    def add_account(self, account):
        logonAccount = {}
        reconcileAccount = {}
        accId = 0

        if "associated.logonAccount.devName" in account.keys() and "associated.logonAccount.account" in account.keys():
            logonAccount["devName"] = account["associated.logonAccount.devName"]
            logonAccount["account"] = account["associated.logonAccount.account"]
            account.pop("associated.logonAccount.devName")
            account.pop("associated.logonAccount.account")
        else:
            if "associated.logonAccount.devName" in account.keys():
                account.pop("associated.logonAccount.devName")
            if "associated.logonAccount.account" in account.keys():
                account.pop("associated.logonAccount.account")
            logonAccount = None

        if "associated.reconcileAccount.devName" in account.keys() and "associated.reconcileAccount.account" in account.keys():
            reconcileAccount["devName"] = account["associated.reconcileAccount.devName"]
            reconcileAccount["account"] = account["associated.reconcileAccount.account"]
            account.pop("associated.reconcileAccount.devName")
            account.pop("associated.reconcileAccount.account")
        else:
            if "associated.reconcileAccount.devName" in account.keys():
                account.pop("associated.reconcileAccount.devName")
            if "associated.reconcileAccount.account" in account.keys():
                account.pop("associated.reconcileAccount.account")
            reconcileAccount = None

        account = self.transform(account)
        devName = account["devName"]
        devId = self.get_device_Id(account["devName"])
        account["devId"] = devId

        account.pop("devName")
        if account["account"] is not None or account["account"] != "":
            account["name"] = account["account"]
            account.pop("account")
        if account["password"] is not None:
            account["credentials"] = account["password"]
            account.pop("password")

        if "cpmDisabled" in account.keys() and account["cpmDisabled"] == False and "cpmDisabledDesc" in account.keys():
            account.pop("cpmDisabled")
            account.pop("cpmDisabledDesc")
        account["type"] = 1 if account["type"] == "local" else 2;

        if "action" in account.keys():
            account.pop("action")

            # add account
        url = self.pvwa + "/api/account"
        payload = json.dumps(account)
        response = requests.request("POST", url, headers=self.headers, data=payload, verify=False)
        if response.status_code != 200:
            raise Exception(response.text)
        if "id" not in json.loads(response.text).keys():
            raise Exception(response.text)
        accId = json.loads(response.text)["id"]

        # associate logon account
        logonAccount_accId = 0;
        if logonAccount is not None:
            logonAccount_accId = self.search_account(logonAccount["devName"], logonAccount["account"])
            if logonAccount_accId != 0:
                self.associate(accId, "logonAccount", logonAccount_accId)
            else:
                print(" - skip data: Does not find the logon account [device={0}, account={1}]".format(
                    logonAccount["devName"], logonAccount["account"]))

        # associate reconcile account
        reconcileAccount_accId = 0;
        if reconcileAccount is not None:
            reconcileAccount_accId = self.search_account(reconcileAccount["devName"], reconcileAccount["account"])
            if reconcileAccount_accId != 0:
                self.associate(accId, "reconcileAccount", reconcileAccount_accId)
            else:
                print(" - skip data: Does not find the reconcile account [device={0}, account={1}]".format(
                    logonAccount["devName"], logonAccount["account"]))

        return accId

    def search_account(self, devName, account):
        url = self.pvwa + "/api/account?filter=devName eq " + devName
        payload = json.dumps(account)
        response = requests.request("GET", url, headers=self.headers, data=payload, verify=False)
        if response.status_code != 200:
            raise Exception(response.text)
        result = json.loads(response.text)
        if int(result["totalElements"]) == 0:
            return 0
        else:
            for item in result["content"]:
                if account == item["account"]:
                    return item["id"]
            return 0;

    def associate(self, accId, assname, linked_accId):
        url = self.pvwa + "/api/account/" + str(accId) + "/associated"
        data = {}
        data[assname] = linked_accId
        payload = json.dumps(data)
        response = requests.request("POST", url, headers=self.headers, data=payload, verify=False)
        if response.status_code != 200:
            raise Exception(response.text)
        return

    def get_device_type(self):
        url = self.pvwa + "/api/system/model/deviceType"
        response = requests.request("GET", url, headers=self.headers, verify=False)
        if response.status_code != 200:
            raise Exception(response.text)
        result = {}
        devTypeList = json.loads(response.text)
        for devType in devTypeList:
            result[devType["name"]] = devType["id"]
        return result


###############################################################################################
def main():
    parser = argparse.ArgumentParser(description="Fill in the sheet and upload devices and accounts", add_help=True)
    parser.add_argument("-a", "--address", help="address to login")
    parser.add_argument("-u", "--username", help="username to login")
    parser.add_argument("-p", "--password", help="password to login")
    parser.add_argument("-f", "--filepath", help="please input excel file path")
    parser.add_argument("-m", "--mode",
                        help='data: upload data only, cpm: trigger cpm only, all: upload data and trigger CPM task')
    args = parser.parse_args()
    if args.address is None or args.username is None or args.password is None or args.filepath is None:
        parser.print_help()
        return
    address = args.address
    username = args.username
    password = args.password
    file_path = args.filepath
    mode = args.mode
    if mode is None:
        mode = "data"
    elif mode not in ["data", "cpm", "all"]:
        raise Exception("mode={0} is not supported...".format(mode))

    print("====================")
    try:

        print("Start Reading content from [{0}]".format(file_path))
        devlist = read_dev_data_from_file(file_path, "Device")
        acclist = read_dev_data_from_file(file_path, "Account")

        pam = PAM(address, username, password)

        if mode in ["data", "all"]:
            logger.info("Start to add device")
            for device in devlist:
                logger.info("Add device: " + device["name"])
                pam.add_device(device)
                logger.info("End of add device")
            logger.info("Finish Device")
        else:
            pass

        logger.info("Start to handle account")
        for account in acclist:
            action = account.get("action", "")
            if mode in ["data", "all"]:
                logger.info(
                    "Add Account for devName=[{0}], account=[{1}]".format(account["devName"], account["account"]))
                accId = pam.add_account(account)
                logger.info("End of Add account")
                if mode == "data":  ## continue the loop, skip to execute cpm action
                    continue
                if account.get("cpmDisabled", False) == False and action != "":
                    pam.trigger_cpm_task(accId, action)
                    logger.info("[CPM] Trigger CPM task [{0}] for devName=[{1}], account=[{2}]".format(action, account["devName"], account["account"]))
                else:
                    logger.info(
                        "[CPM] Skip trigger CPM task [{0}] for devName=[{1}], account=[{2}], because of cpmDisabled=True or action is empty".format(
                            action, account["devName"], account["account"]))
                continue
            elif mode == "cpm":
                accId = pam.search_account(account["devName"], account["account"])
                if account.get("cpmDisabled", False) == False:
                    pam.trigger_cpm_task(accId, action)
                    logger.info("[CPM] Trigger CPM task [{0}] for devName=[{1}], account=[{2}]".format(action, account[
                        "devName"], account["account"]))
        logger.info("End of handle account from excel sheet")
    except Exception as e:
        track = traceback.format_exc()
        logger.info(e)
        logger.info(track)


if __name__ == "__main__":
    main()