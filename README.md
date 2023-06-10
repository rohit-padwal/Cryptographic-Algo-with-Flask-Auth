# User-Authentication-in-Flask

## Set up & Installation.

### create an environment 
                    
**Windows**
          
```bash
cd User-Authentication-in-Flask
py -3 -m venv venv

```
          
**macOS/Linux**
          
```bash
cd User-Authentication-in-Flask
python3 -m venv venv

```

### 2 .Activate the environment
          
**Windows** 

```venv\Scripts\activate```
          
**macOS/Linux**

```. venv/bin/activate```
or
```source venv/bin/activate```

### 3 .Install the requirements

Applies for windows/macOS/Linux

```
cd main
pip install -r requirements.txt
```
### 4 .Migrate/Create a database

```python manage.py```

### 5. Run the application 

**For linux and macOS**
Make the run file executable by running the code

```chmod 777 run```

Then start the application by executing the run file

```./run```

**On windows**
```
set FLASK_APP=routes
flask run
```

### 6. REFERENCES 

```1 https://github.com/ondiekelijah/User-Authentication-in-Flask```

```2 https://github.com/memudualimatou/INSURANCE-CHARGES-WEB-APPLICATION```

```3 https://memudualimatou.medium.com/creating-a-select-tag-on-a-web-application-using-flask-python-fffe6ea0c939```

```4 https://www.geeksforgeeks.org/encrypt-and-decrypt-files-using-python/```

```5 https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/```

```6 https://analyticsindiamag.com/implementing-encryption-and-decryption-of-data-in-python/```

