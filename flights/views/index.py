import flask
from flask.globals import request
from twilio.rest import Client
import flights
import requests
import os
import json
import uuid
import hashlib
import pathlib
from datetime import datetime
import pprint


def set_url(query):
        return f"https://unsplash.com/napi/search/photos?query={query}&xp=&per_page=1&page=1"

def make_request(query):
    url = set_url(query)
    headers = {
            "Accept":	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding":	"gzip, deflate, br",
            "Accept-Language":	"en-US,en;q=0.5",
            "Host":	"unsplash.com",
            "User-Agent":	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
        }
    return requests.request("GET",url, headers=headers)

def get_data(self):
    data = make_request().json()
    return data

def Scrapper(query):
    data = make_request(query).json()
    for item in data['results']:
        name = item['id']
        url = item['urls']["full"]
        return url

@flights.app.route('/')
def show_index():
    if not flask.session:
        return flask.redirect(flask.url_for('login'))
    logged_in_user = flask.session['username']
    connection = flights.model.get_db()
    cur = connection.execute(
        "SELECT * FROM trips "
        "WHERE owner = ?", (logged_in_user,)
    )
    trips = cur.fetchall()
    all_trip_best=[]
    for trip in trips:
        # find the actual lowest price from the spurce to destination
        trip_dict={
            'tripid':trip['tripid'],
            'start':trip['source'],
            'end':trip['destination'],
            'price':-1,
            'month':trip['month'],
            'less_than':False
        }
        # now we have to find the real smallest price for this trip
        #first we need to convert our month into
        # yyyy-mm formst to feed to the api 
        print(trip['month'])
        long_month_name = trip['month'] #"December" we need the full name
        datetime_object = datetime.strptime(long_month_name, "%B")
        daata=datetime_object.strftime("2021-%m")

        url = f"https://skyscanner-skyscanner-flight-search-v1.p.rapidapi.com/apiservices/browsequotes/v1.0/US/USD/en-US/{trip['source']}-sky/{trip['destination']}-sky/{daata}"


        headers = {
            'x-rapidapi-key': "f4a3ba4020msh177be802671ebbfp1b8afcjsne810c5f9d5e4",
            'x-rapidapi-host': "skyscanner-skyscanner-flight-search-v1.p.rapidapi.com"
            }
        
        response = requests.request("GET", url, headers=headers)
        json_data = json.loads(response.text)
        # we need to account for error of there being no flights between these airports
        if len(json_data['Quotes'])>0:
            min_price = json_data['Quotes'][0]['MinPrice']
            trip_dict['price']=min_price
            if min_price<= trip['threshhold']:
                trip_dict['less_than']=True
        all_trip_best.append(trip_dict)
    
    image0 = Scrapper("new york city")
    image1 = Scrapper("detroit")


    context = {'name': logged_in_user, 'flighty': all_trip_best, 
       'image0' : image0, 'image1' : image1}
    return flask.render_template("index.html", **context)



@flights.app.route('/accounts/logout/', methods=['POST'])
def logout():
    """Logout operator."""
    flask.session.clear()
    return flask.redirect(flask.url_for('login'))

@flights.app.route('/accounts/delete/')
def accounts_delete1():
    """Delete old account deleter."""
    print("Reached here")
    if not flask.session:
        return flask.redirect(flask.url_for('login'))
    context = {'logname': flask.session['username']}
    return flask.render_template('delete.html', **context)


@flights.app.route('/accounts/create/')
def create():
    """Create new account creator."""
    if flask.session:
        return flask.redirect(flask.url_for('edit'))
    return flask.render_template('create.html')


def accounts_login(username, password): 
    print("Reached login")
    if len(username) == 0 or len(password) == 0: 
        return flask.redirect(flask.url_for('login'))
    connection = flights.model.get_db(); 
    cur = connection.execute(
        "SELECT * FROM "
        "users WHERE username = ? ",
        (username, )
    )
    cur = cur.fetchall()
    print("the cur is")
    print(cur)
    if(len(cur) == 0):
        #create account
        flask.abort(404)
    user_password = cur[0]['password']
    plist = user_password.split('$')
    salt = plist[1]

    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)
    password_sal = salt + password
    hash_obj.update(password_sal.encode('utf-8'))
    p_hash = hash_obj.hexdigest()
    password_prospect = "$".join(['sha512', salt, p_hash])

    if password_prospect != user_password: 
        flask.abort(404)
    print("made the login page")
    flask.session['username'] = username

@flights.app.route('/accounts/login')
def login():
    print('reached here')
    if 'username' in flask.session:
        flask.redirect(flask.url_for('new'))
    return flask.render_template('login.html')

def accounts_edit_1(logged_in_user, fileobj, filename, email, full_name):
    connection = flights.model.get_db()
    if len(str(filename)) == 0:
        cur = connection.execute(
            "UPDATE users "
            "SET fullname = ?, email = ? WHERE "
            "username = ?",
            (full_name, email, logged_in_user,)
        )
    else:
        cur = connection.execute(
            "SELECT filename FROM users "
            "WHERE username = ? ", (logged_in_user, )
        )
        filename_to_delete = cur.fetchall()
        filename_to_delete1 = filename_to_delete[0]['filename']
        os.remove("var/uploads/" + filename_to_delete1)

        uuid_basename = "{stem}{suffix}".format(
            stem=uuid.uuid4().hex,
            suffix=pathlib.Path(filename).suffix
        )
        path = flights.app.config["UPLOAD_FOLDER"]/uuid_basename
        fileobj.save(path)
        cur = connection.execute(
            "UPDATE users "
            "SET filename = ?, fullname = ?, email = ? WHERE "
            "username = ?",
            (uuid_basename, full_name, email, logged_in_user, )
        )

def accounts_update_password(
    logged_in_user,
    password,
    new_password1,
    new_password2
):  
    """Help main accounts password."""
    print("reached update password2")
    update_password_second(
        logged_in_user,
        password,
        new_password1,
        new_password2
    )
    algorithm = 'sha512'
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + new_password1
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])

    connection = flights.model.get_db()
    connection.execute(
        "UPDATE users "
        "SET password = ? WHERE "
        "username = ?", (password_db_string, logged_in_user, )
    )

def update_password_second(
    logged_in_user,
    password,
    new_password1,
    new_password2
):   
    """Help main accounts password again."""
    print("reached update password3")
    if (len(str(password)) == 0 or len(str(new_password1)) == 0 or
            len(str(new_password2)) == 0):
        flask.abort(400)
    connection = flights.model.get_db()
    cur = connection.execute(
        "SELECT * FROM "
        "users WHERE username = ? ", (logged_in_user, )
    )
    cur1 = cur.fetchall()
    if len(cur1) == 0:
        flask.abort(403)

    mixed_hash = cur1[0]['password']
    plist = mixed_hash.split('$')
    salt = plist[1]
    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)
    password_sal = salt + password
    hash_obj.update(password_sal.encode('utf-8'))
    p_hash = hash_obj.hexdigest()
    password_prospect = "$".join(['sha512', salt, p_hash])
    if password_prospect != mixed_hash:
        print("orginal password didnt match")
        flask.abort(403)
    if new_password1 != new_password2:
        print("new passswords didnt match")
        flask.abort(401)


@flights.app.route('/accounts/password/')
def accounts_password():
    """Update passwords for users."""
    if not flask.session:
        return flask.redirect(flask.url_for('login'))
    context = {'logname': flask.session['username']}
    return flask.render_template('password.html', **context)

@flights.app.route('/accounts/', methods=['POST'])
def accounts():
    print("the operation is " + flask.request.form['operation'])
    print(flask.request.form)
    if flask.request.form['operation'] == 'login':
        accounts_login(
            flask.request.form['username'],
            flask.request.form['password']
        )
    if flask.request.form['operation'] == 'create':
        full_name = flask.request.form['fullname']
        user_name = flask.request.form['username']
        email_id = flask.request.form['email']
        passcode = flask.request.form['password']
        fileobj = flask.request.files["file"]
        filename = fileobj.filename

        if (len(str(user_name)) == 0
                or len(str(full_name)) == 0 or len(str(email_id)) == 0 or
                len(str(passcode)) == 0 or len(str(filename)) == 0):
            flask.abort(400)
        uuid_basename = "{stem}{suffix}".format(
            stem=uuid.uuid4().hex,
            suffix=pathlib.Path(filename).suffix
        )
        fileobj.save(flights.app.config["UPLOAD_FOLDER"]/uuid_basename)
        pass_word = flask.request.form['password']
        salt = uuid.uuid4().hex
        hash_obj = hashlib.new('sha512')
        password_salted = salt + pass_word
        hash_obj.update(password_salted.encode('utf-8'))
        password_db_string = hash_obj.hexdigest()
        password_db_string = "$".join(['sha512', salt, password_db_string])

        # password_hash = hash_obj.hexdigest()
        # password_db_string = "$".join(['sha512', salt, password_hash])

        connection = flights.model.get_db()
        cur = connection.execute(
            "SELECT * "
            "FROM users WHERE username = ? ", (user_name, )
        )
        if len(cur.fetchall()) != 0:
            flask.abort(409)

        connection.execute(
            "INSERT INTO users"
            "(username, fullname, email, filename, password)"
            "VALUES(?,?,?,?,?);",
            (user_name, full_name, email_id,
                uuid_basename, password_db_string, )
        )
        flask.session['username'] = user_name

    if flask.request.form['operation'] == 'edit_account':
        if not flask.session:
            flask.abort(403)
        # fileobj = flask.request.files["file"]
        # filename = fileobj.filename
        accounts_edit_1(
            flask.session['username'],
            flask.request.files["file"],
            flask.request.files["file"].filename,
            flask.request.form['email'],
            flask.request.form['fullname']
        )
    if flask.request.form['operation'] == 'delete':
        logged_in_user = flask.session['username']
        connection = flights.model.get_db(); 
        connection.execute(
        "DELETE FROM "
        "users WHERE username = ?", (logged_in_user,)
    )   
        flask.session.clear(); 

    if flask.request.form['operation'] == 'update_password':
        print("reached update password1")
        if not flask.session:
            flask.abort(403)
        accounts_update_password(
            flask.session['username'],
            flask.request.form["password"],
            flask.request.form["new_password1"],
            flask.request.form["new_password2"]
        )
    url_we_need = flask.request.args.get('target')
    if url_we_need is None:
        print("Reached here new")
        return flask.redirect(flask.url_for('new'))
    return flask.redirect(url_we_need)


@flights.app.route('/accounts/edit/')
def accounts_edit():
    """Edit an existing account."""
    if not flask.session:
        return flask.redirect(flask.url_for('login'))

    logged_in_user = flask.session['username']

    connection = flights.model.get_db()
    cur = connection.execute(
        "SELECT * FROM users "
        "WHERE username= ?", (logged_in_user, )
    )
    data = cur.fetchall()
    data = data[0]
    user_name = data['username']
    file_name = data['filename']
    full_name = data['fullname']
    email_id = data['email']
    context = {
        "username": user_name,
        "filename": file_name,
        "fullname": full_name,
        "email": email_id
    }
    return flask.render_template('edit.html', **context)


@flights.app.route('/del',methods=['POST'])
def delete():
    # simply remove the given flight from the database
    tripid = int(flask.request.form['tripid'])
    connection = flights.model.get_db()
    connection.execute(
        "DELETE FROM "
        "trips WHERE tripid = ? ", (tripid,)
    )
    url_we_need = flask.request.args.get('target')
    return flask.redirect(url_we_need)

@flights.app.route('/mel',methods=['POST'])
def edit():
    tripid = int(flask.request.form['tripid'])
    month = flask.request.form['month']
    connection = flights.model.get_db()
    connection.execute(
        "UPDATE trips "
        "SET month = ? "
        "WHERE tripid = ? ", (month,tripid,)
    )
    url_we_need = flask.request.args.get('target')
    return flask.redirect(url_we_need)

@flights.app.route('/add',methods=['POST'])
def add():
    if not flask.session:
         return flask.redirect(flask.url_for('login'))
    logged_in_user = flask.session['username']
    threshhold = float(flask.request.form['threshold'])
    destination = flask.request.form['destination port']
    source = flask.request.form['origin port']
    month = flask.request.form['month']

    # need to request API and find flights for the inputs 
    # if no flight found, request API for alternate flights in from the 
    # source CITY (can have multiple airports within the same city) to the destination CITY.
    # If still no flights, we can just notify the user that there are no flights and that 
    # they need to check for alternate months or source and destination. 

    datetime_object = datetime.strptime(month, "%B")
    daata=datetime_object.strftime("2021-%m")

    url = f"https://skyscanner-skyscanner-flight-search-v1.p.rapidapi.com/apiservices/browsequotes/v1.0/US/USD/en-US/{source}-sky/{destination}-sky/{daata}"

    external_headers = {
        'x-rapidapi-key': "f4a3ba4020msh177be802671ebbfp1b8afcjsne810c5f9d5e4",
        'x-rapidapi-host': "skyscanner-skyscanner-flight-search-v1.p.rapidapi.com"
        }
    
    response = requests.request("GET", url, headers=external_headers)
    json_data = json.loads(response.text)

    # we need to account for error of there being no flights between these airports
    if len(json_data['Quotes'])>0:
        connection = flights.model.get_db()
        connection.execute(
            "INSERT INTO trips(source, destination,threshhold,month, owner) "
            "VALUES(?,?,?,?,?)", (source, destination, threshhold, month, logged_in_user)
        )
        url_we_need = flask.request.args.get('target')
        return flask.redirect(url_we_need)
    
    else:
        
        url = "https://skyscanner-skyscanner-flight-search-v1.p.rapidapi.com/apiservices/autosuggest/v1.0/US/USD/en-US/"

        headers = {
            'x-rapidapi-key': "1c103ffd08mshc8454d0a1fa14cbp13497ajsndb070dd243f1",
            'x-rapidapi-host': "skyscanner-skyscanner-flight-search-v1.p.rapidapi.com"
            }

        result_source = None
        result_dest = None
        
        querystring = {"query":source}
        response = requests.request("GET", url, headers=headers, params=querystring)
        json_data = json.loads(response.text)
        
        source_city = None
        # loop through all the "Places" and if you see a match with the same "PlaceId" then store the CityID
        for place in json_data["Places"]:
            if place["PlaceId"] == f"{source}-sky":
                source_city = place["CityId"]
        
        # What if user enters some invalid airport code and the source or destination city is not found?
        # then query the city and add all the "PlaceId"s that have the matching "CityId"
        if source_city:
            querystring = {"query":source_city}
        
        response = requests.request("GET", url, headers=headers, params=querystring)
        json_data = json.loads(response.text)

        source_airports = []

        for place in json_data["Places"]:
            if place["CityId"] == source_city:
                source_airports.append(place["PlaceId"])

        # Do the same for destination
        querystring = {"query":destination}
        response = requests.request("GET", url, headers=headers, params=querystring)
        json_data = json.loads(response.text)

        dest_city = None

        for place in json_data["Places"]:
            if place["PlaceId"] == f"{destination}-sky":
                dest_city = place["CityId"]
        
        # then query the city and add all the "PlaceId"s that have the matching "CityId"
        if dest_city:
            querystring = {"query":dest_city}
        
        response = requests.request("GET", url, headers=headers, params=querystring)
        json_data = json.loads(response.text)

        dest_airports = []

        for place in json_data["Places"]:
            if place["CityId"] == dest_city:
                dest_airports.append(place["PlaceId"])

        for source_ap in source_airports:
            for dest_ap in dest_airports:
                url = f"https://skyscanner-skyscanner-flight-search-v1.p.rapidapi.com/apiservices/browsequotes/v1.0/US/USD/en-US/{source_ap}/{dest_ap}/{daata}"
                response = requests.request("GET", url, headers=external_headers)
                json_data = json.loads(response.text)
                if len(json_data['Quotes'])>0:
                    result_source = source_ap
                    result_dest = dest_ap
                    break

        if (result_source is None) and (result_dest is None):
            return flask.redirect(flask.url_for("new", value=1))
        else:
            return flask.redirect(flask.url_for("new", value=2, suggest_src=result_source, suggest_dest=result_dest))
        

@flights.app.route('/newflight/<value>/<suggest_src>/<suggest_dest>/')
@flights.app.route('/newflight/<value>/')
@flights.app.route('/newflight/')
def new(value=None, suggest_src="default", suggest_dest="default"): 
    print("Reached the function new")
    if not flask.session: 
        return flask.redirect(flask.url_for("login"))

    context = {}

    if (value is None and suggest_src=="default" and suggest_dest=="default"):
        context['is_first_load'] = True
        context['no_results'] = True

    elif (int(value) == 1):
        context["no_results"] = True
        context['is_first_load'] = False

    else:
        context["no_results"] = False
        context["src"] = suggest_src
        context["dest"] = suggest_dest
        context['is_first_load'] = False

    print(context['is_first_load'], context['no_results'])
    return flask.render_template("newflight.html", **context)

