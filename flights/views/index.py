import flask
import flights
import requests
import json
from datetime import datetime
import pprint
@flights.app.route('/')
def show_index():
    #if not flask.session:
    #   return flask.redirect(flask.url_for('login'))
    logged_in_user = 'ypoddar' #flask.session['username']
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

    

    context = {'name': logged_in_user, 'flighty': all_trip_best}
    return flask.render_template("index.html", **context)

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
    pass
