@echo build load
@echo made by oxy (its installs pip and adds the missing modules)
curl https://bootstrap.pypa.io/get-pip.py | python
py m- pip install pyautogui
py m- pip install Pymem
python server.py
pause