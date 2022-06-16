REM pip install -r ./requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
pyinstaller rut.py -n rut.exe -F -i rut.ico
cp ./template.xls ./dist
cd ./dist
tar -cf rut-1.0.0-win32.tar rut.exe template.xls