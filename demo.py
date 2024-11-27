import requests
import json

# 设置基本参数
BASE_URL = ""  #机场网址
EMAIL = ""  #管理员邮箱
PASSWORD = ""  #管理员密码

# 创建会话
session = requests.Session()

def login():
    login_url = f"{BASE_URL}/api/v1/passport/auth/login"
    headers = {
        'accept': '*/*',
        'accept-language': 'zh-TW,zh-CN;q=0.9,zh;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': BASE_URL,
        'referer': f"{BASE_URL}/xddg8888",
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
    }

    payload = {
        'email': EMAIL,
        'password': PASSWORD
    }

    response = session.post(login_url, headers=headers, data=payload)

    if response.ok:
        print("登录成功1", response.text)
        data = response.json().get("data", {})
        xddg8888_auth = data.get("auth_data")
        print("登录成功2", xddg8888_auth)
        get_nodes(xddg8888_auth)
    else:
        print("登录失败:")

def get_nodes(auth):
    url = f"{BASE_URL}/api/v1/xddg8888/server/manage/getNodes"
    headers = {
        'accept': '*/*',
        'accept-language': 'zh-TW,zh-CN;q=0.9,zh;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5',
        'authorization': auth,
        'priority': 'u=1, i',
        'referer': 'https://nb.xddg.tk/xddg8888',
        'sec-ch-ua': '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
    }

    response = requests.get(url, headers=headers)

    if response.ok:
        nodes = response.json().get("data", [])
        print("获取节点信息成功:", nodes)

        # 需要修改节点端口的ID
        node_id = 37
        new_port = 45649  # 新的端口
        new_server_port = 45649  # 新的服务器端口

        # 找到 Node ID 为 37 的节点
        node_to_modify = next((node for node in nodes if node['id'] == node_id), None)

        if node_to_modify:
            modify_node(node_to_modify, new_port, new_server_port, auth)
        else:
            print(f"未找到 ID 为 {node_id} 的节点")
    else:
        print("获取节点信息失败:", response.status_code, response.text)

def modify_node(node, new_port, new_server_port, auth):
    url = f"{BASE_URL}/api/v1/xddg8888/server/vmess/save"
    headers = {
        'accept': '*/*',
        'accept-language': 'zh-TW,zh-CN;q=0.9,zh;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5',
        'authorization': auth,
        'content-type': 'application/json',  # 更改为 application/json
        'origin': BASE_URL,
        'priority': 'u=1, i',
        'referer': f"{BASE_URL}/xddg8888",
    }

    # 构造请求数据
    data = {
        'id': node['id'],
        'group_id': node['group_id'],  # 在这里可能需要处理 group_id，确保它是一个列表
        'route_id': '',
        'name': node['name'],
        'parent_id': node['parent_id'],
        'host': node['host'],
        'port': new_port,
        'server_port': new_server_port,
        'tls': node['tls'],
        'tags': node['tags'],  # 同样要确认 tags 是一个列表
        'rate': node['rate'],
        'network': node['network'],
        'rules': node['rules'],
        'networkSettings': node['networkSettings'],
        'tlsSettings': node['tlsSettings'],
        'ruleSettings': node['ruleSettings'],
        'dnsSettings': node['dnsSettings'],
        'show': node['show'],
        'sort': node['sort'],
        'created_at': node['created_at'],
        'updated_at': node['updated_at'],
        'type': node['type'],
        'online': node['online'],
        'last_check_at': node['last_check_at'],
        'last_push_at': node['last_push_at'],
        'available_status': node['available_status']
    }

    # 输出请求数据，用于调试
    print("准备发送的数据:", json.dumps(data, ensure_ascii=False, indent=4))

    try:
        response = requests.post(url, headers=headers, json=data)  # 使用 json 参数发送请求
        response.raise_for_status()  # 如果响应状态不为200，会抛出异常
        
        print("节点信息修改成功:", response.json())
    except requests.exceptions.RequestException as e:
        print("修改节点信息失败:", e)

if __name__ == "__main__":
    login()
