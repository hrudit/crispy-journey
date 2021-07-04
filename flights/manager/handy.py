import flask
import flights

@flights.app.route('/appy')
def throw_index():
    """Display / route."""
    context = {}
    return flask.render_template("tindex.html", **context)