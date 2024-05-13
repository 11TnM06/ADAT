
import GVM.gvm as gvm
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

if __name__ == '__main__':
    #target = gvm.create_target("b", ["192.168.0.15"], "a", "33d0cd82-57c6-11e1-8ed1-406186ea4fc5")
    #port_lists = gvm.get_port_lists()
    #task = gvm.delete_task("8049d533-01ff-4478-8fd1-9194f58737d0")
    task = gvm.create_task("b", "e3efebc5-fc0d-4cb6-b1b4-55309d0a89f6", 
        "ef719a4d-088c-48db-a403-060f159c6f3d", None, None)
    print(task)

