REM pip install -r ./requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
pyinstaller rut.py -n rut.exe -F -i rut.ico
cp ./template.xls ./dist