from app import app, db
from flask_socketio import SocketIO
socketio = SocketIO(app)
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
