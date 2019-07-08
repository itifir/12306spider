# -*- coding: utf-8 -*-
import json
import re
from urllib import parse
import requests
import time
from fake_useragent import UserAgent
# 禁用安全请求警告
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
disable_warnings(InsecureRequestWarning)


class Ticket12306(object):
    def __init__(self):
        ua = UserAgent(verify_ssl=False)
        self.headers = {
            "User-Agent": ua.random,
            "Host": "kyfw.12306.cn",
            "Referer": "https://kyfw.12306.cn/otn/passport?redirect=/otn/"
        }
        self.session = requests.session()
        self.session.verify = False



    # 登陆
    def login(self):
        # 打开登录页面
        url = "https://kyfw.12306.cn/otn/login/init"
        self.session.get(url, headers=self.headers)
        # 发送验证码
        if not self.captcha():
            return False

        # 发送登录信息
        data = {
            "username": "15184341720",
            "password": "wocao102911",
            "appid": "otn"
        }
        url = "https://kyfw.12306.cn/passport/web/login"
        response = self.session.post(url, headers=self.headers, data=data)
        if response.status_code == 200:
            result = json.loads(response.text)
            print(result.get("result_message"), result.get("result_code"))
            if result.get("result_code") != 0:
                return False

        data = {
            "appid": "otn"
        }
        url = "https://kyfw.12306.cn/passport/web/auth/uamtk"
        response = self.session.post(url, headers=self.headers, data=data)
        if response.status_code == 200:
            result = json.loads(response.text)
            print(result.get("result_message"))
            newapptk = result.get("newapptk")

        data = {
            "tk": newapptk
        }
        url = "https://kyfw.12306.cn/otn/uamauthclient"
        response = self.session.post(url, headers=self.headers, data=data)
        if response.status_code == 200:
            print(response.text)

        url = "https://kyfw.12306.cn/otn/login/conf"
        response = self.session.post(url, headers=self.headers)
        print(response)

        url = "https://kyfw.12306.cn/otn/index/initMy12306Api"
        response = self.session.post(url, headers=self.headers)
        if response.status_code == 200 and response.text.find("用户名") != -1:
            return True
        return False

    # 验证码处理
    def captcha(self):
        data = {
            "login_site": "E",
            "module": "login",
            "rand": "sjrand",
            "0.17231872703389062": ""
        }

        # 获取验证码
        param = parse.urlencode(data)
        url = "https://kyfw.12306.cn/passport/captcha/captcha-image?{}".format(param)
        response = self.session.get(url, headers=self.headers)
        # 把验证码图片保存到本地
        with open('img.jpg', 'wb') as f:
            f.write(response.content)
        # result = decode('img.jpg', codetype=6701)
        result = input("请输入验证码：")
        positions = self.checkVerification(result)
        # 发送验证码
        data = {
            "answer": positions,
            "login_site": "E",
            "rand": "sjrand"
        }

        url = "https://kyfw.12306.cn/passport/captcha/captcha-check"
        response = self.session.post(url, headers=self.headers, data=data)
        if response.status_code == 200:
            result = json.loads(response.text)
            print(result.get("result_message"))
            return True if result.get("result_code") == "4" else False
        return False

    # 验证码坐标处理
    def checkVerification(selef, solution):
        soList = []
        for i in range(len(solution)):
            soList.append(solution[i])
        yanSol = ['35,35', '105,35', '175,35', '245,35', '35,105', '105,105', '175,105', '245,105']
        yanList = []
        for item in soList:
            yanList.append(yanSol[int(item) - 1])
        # 正确验证码的坐标拼接成字符串，作为网络请求时的参数
        yanStr = ','.join(yanList)
        return yanStr

    # 校验是否登陆
    def checkUser(self):
        data = {"_json_att": ""}
        url = "https://kyfw.12306.cn/otn/login/checkUser"
        response = self.session.post(url, data=data, headers=self.headers)
        dict_data = json.loads(response.content.decode())
        return dict_data["status"]

    # 爬取车票信息
    def queryTickets(self):
        # 访问列表页,并且可以通过参数定制化需要抢的日期和地点
        url = "https://kyfw.12306.cn/otn/leftTicket/queryZ?leftTicketDTO.train_date=2019-02-15&leftTicketDTO.from_station=ICW&leftTicketDTO.to_station=LCW&purpose_codes=ADULT"
        response = self.session.get(url, headers=self.headers)
        dict_data = json.loads(response.content.decode())

        if str(dict_data["status"]) == "True":
            dict_ticket = dict_data["data"]["result"]
            maps = dict_data['data']['map']
            for item in dict_ticket:
                trainDict = {}
                trainInfo = item.split('|')
                if trainInfo[8] == "10:16" and len(trainInfo[0]) > 0:
                    trainDict['secretStr'] = trainInfo[0]

                    trainDict['trainNumber'] = trainInfo[2]  # 5l0000D35273

                    trainDict['trainName'] = trainInfo[3]  # 车次名称，如D352

                    trainDict['fromTelecode'] = trainInfo[6]  # 出发地电报码

                    trainDict['toTelecode'] = trainInfo[7]  # 出发地电报码

                    trainDict['fromStation'] = maps[trainInfo[6]]  # 上海

                    trainDict['toStation'] = maps[trainInfo[7]]  # 成都

                    trainDict['departTime'] = trainInfo[8]  # 出发时间

                    trainDict['arriveTime'] = trainInfo[9]  # 到达时间

                    trainDict['totalTime'] = self.getDuration(trainInfo[10])  # 总用时

                    trainDict['leftTicket'] = trainInfo[12]  # 余票

                    trainDict['trainDate'] = trainInfo[13]  # 20180822

                    trainDict['trainLocation'] = trainInfo[15]  # H2

                    trainDict['otherSeat'] = trainInfo[22]  # 其他

                    return trainDict

    # 下单
    def submitOrderRequest(self, trainDict):
        data = {"secretStr": parse.unquote(trainDict['secretStr']),
                "train_date": "2019-02-15",
                "back_train_date": "2019-02-11",
                "tour_flag": "dc",
                "purpose_codes": "ADULT",
                "query_from_station_name": "成都东",
                "query_to_station_name": "隆昌",
                "undefined": ""}
        url = "https://kyfw.12306.cn/otn/leftTicket/submitOrderRequest"
        self.session.post(url, data=data, headers=self.headers)


        data = {
            '_json_att': ''
        }
        url = "https://kyfw.12306.cn/otn/confirmPassenger/initDc"
        response = self.session.post(url, data=data)
        try:
            repeatSubmitToken = re.findall(r"var globalRepeatSubmitToken = '(.*?)'", response.content.decode())[0]
            keyCheckIsChange = re.findall(r"key_check_isChange':'(.*?)'", response.text)[0]

            data = {
                '_json_att': '',
                'REPEAT_SUBMIT_TOKEN': repeatSubmitToken
            }
            url = "https://kyfw.12306.cn/otn/confirmPassenger/getPassengerDTOs"
            res = self.session.post(url, data=data)
            passengers = res.json()['data']['normal_passengers']

            for passenger in passengers:
                if passenger['passenger_name'] == "张雄":
                    print("开始抢票")
                    self.checkOrderInfo("O", repeatSubmitToken, passenger)
                    self.getQueueCount("O", repeatSubmitToken, keyCheckIsChange, trainDict, passenger)
                else:
                    print('无法购票')
        except:
            print('获取Token参数失败')
            return


    def checkOrderInfo(self, seatType, repeatSubmitToken, passenger):
        passengerTicketStr = '{},{},{},{},{},{},{},N'.format(seatType, passenger['passenger_flag'],
                                                                    passenger['passenger_type'],
                                                                    passenger['passenger_name'],
                                                                    passenger['passenger_id_type_code'],
                                                                    passenger['passenger_id_no'],
                                                                    passenger['mobile_no'])
        oldPassengerStr = '{},{},{},1_'.format(passenger['passenger_name'], passenger['passenger_id_type_code'],
                                                  passenger['passenger_id_no'])
        data = {
            '_json_att'          : '',
            'bed_level_order_num': '000000000000000000000000000000',
            'cancel_flag'        : '2',
            'oldPassengerStr'    : oldPassengerStr,
            'passengerTicketStr' : passengerTicketStr,
            'randCode'           : '',
            'REPEAT_SUBMIT_TOKEN': repeatSubmitToken,
            'tour_flag'          : 'dc',
            'whatsSelect'        : '1'
        }

        res = self.session.post('https://kyfw.12306.cn/otn/confirmPassenger/checkOrderInfo', data=data)
        dict = res.json()
        if dict['data']['submitStatus']:
            print('系统校验订单信息成功')
            if dict['data']['ifShowPassCode'] == 'Y':
                print('需要再次验证')
                return True
            if dict['data']['ifShowPassCode'] == 'N':
                return False
        else:
            print('系统校验订单信息失败')
            return False


    def getQueueCount(self,seatType,repeatSubmitToken,keyCheckIsChange,trainDict,passenger):
        data = {
            '_json_att'           : '',
            'fromStationTelecode' : trainDict['fromTelecode'],
            'leftTicket'          : trainDict['leftTicket'],
            'purpose_codes'       : '00',
            'REPEAT_SUBMIT_TOKEN' : repeatSubmitToken,
            'seatType'            : seatType,
            'stationTrainCode'    : trainDict['trainName'],
            'toStationTelecode'   : trainDict['toTelecode'],
            'train_date'          : self.getTrainDate(trainDict['trainDate']),
            'train_location'      : trainDict['trainLocation'],
            'train_no'            : trainDict['trainNumber'],
        }

        res = self.session.post('https://kyfw.12306.cn/otn/confirmPassenger/getQueueCount', data=data)


        if res.json()['status']:
            print('系统获取队列信息成功')
            self.confirmSingleForQueue(seatType, repeatSubmitToken, keyCheckIsChange, passenger, trainDict)

        else:
            print('系统获取队列信息失败')
            return


    def confirmSingleForQueue(self,seatType,repeatSubmitToken,keyCheckIsChange,passenger,trainDict):
        passengerTicketStr = '{},{},{},{},{},{},{},N'.format(seatType, passenger['passenger_flag'],
                                                             passenger['passenger_type'],
                                                             passenger['passenger_name'],
                                                             passenger['passenger_id_type_code'],
                                                             passenger['passenger_id_no'],
                                                             passenger['mobile_no'])
        oldPassengerStr = '{},{},{},1_'.format(passenger['passenger_name'], passenger['passenger_id_type_code'],
                                               passenger['passenger_id_no'])
        data = {
            'passengerTicketStr': passengerTicketStr,
            'oldPassengerStr': oldPassengerStr,
            'randCode': '',
            'purpose_codes': '00',
            'key_check_isChange': keyCheckIsChange,
            'leftTicketStr': trainDict['leftTicket'],
            'train_location': trainDict['trainLocation'],
            'choose_seats': '',
            'seatDetailType': '000',
            'whatsSelect': '1',
            'roomType': '00',
            'dwAll': 'N',
            '_json_att': '',
            'REPEAT_SUBMIT_TOKEN': repeatSubmitToken,
        }
        res = self.session.post('https://kyfw.12306.cn/otn/confirmPassenger/confirmSingleForQueue', data=data)
        if res.json()['status']['submitStatus'] == 'true':
            print('已完成订票，请前往12306进行支付')
        else:
            print('订票失败,请稍后重试!')

    def getTrainDate(self, dateStr):
        # 返回格式 Wed Aug 22 2018 00: 00:00 GMT + 0800 (China Standard Time)
        # 转换成时间数组
        timeArray = time.strptime(dateStr, "%Y%m%d")
        # 转换成时间戳
        timestamp = time.mktime(timeArray)
        # 转换成localtime
        timeLocal = time.localtime(timestamp)
        # 转换成新的时间格式
        GMT_FORMAT = '%a %b %d %Y %H:%M:%S GMT+0800 (China Standard Time)'
        timeStr = time.strftime(GMT_FORMAT, timeLocal)
        return timeStr

    def getDuration(self, timeStr):
        duration = timeStr.replace(':', '时') + '分'
        if duration.startswith('00'):
            return duration[4:]
        return duration


if __name__ == '__main__':
    ticket = Ticket12306()
    if ticket.login():
        print("登陆成功")
        print("查询车票")
        trainDict = ticket.queryTickets()
        # 校验是否登陆
        if ticket.checkUser():
            # 下单
            ticket.submitOrderRequest(trainDict)

    else:
        print("Failed")
