# 3heroes
sudo apt-get update<br>
sudo install git python3 mysql-server<br>
git clone https://github.com/thanhdevil9699/3heroes.git<br>

### Cai dat MySQL:
sudo mysql_secure_installation<br>
sudo mysql<br>
SELECT user,authentication_string,plugin,host FROM mysql.user;<br>
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '09061999';<br>
FLUSH PRIVILEGES;<br>

### Mo Terminal o thu muc vua clone:
python3 -m venv venv<br>
source venv/bin/activate<br>
pip3 install --upgrade pip setuptools wheel<br>
pip3 install -r requirements.txt<br>
python3 run.py<br>

### Mo MySQL o thu muc vua clone:
mysql -u root -p<br>
source database.sql<br>
