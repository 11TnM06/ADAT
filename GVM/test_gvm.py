
import GVM.gvm as gvm
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

if __name__ == '__main__':
    target = gvm.get_target("f3f96466-87f0-4acc-875c-d3ddf004ad0f")
    target = ET.fromstring(target).find('target')
    print(target.find('in_use').text)
    target_data = {"name": target.find('name').text, "id": target.attrib['id'],
        "hosts": target.find('hosts').text, "comment": target.find('comment').text,
        "port_list": target.find('port_list').find('name').text,
        "hosts": target.find('hosts').text,
        "in_use": target.find('in_use').text,
        }
    print(target_data)
