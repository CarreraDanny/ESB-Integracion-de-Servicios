from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:12345@localhost/transporte'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Reserva(db.Model):
    __tablename__ = 'Reservas'
    ID_Reserva = db.Column(db.Integer, primary_key=True)
    ID_Horario = db.Column(db.Integer, db.ForeignKey('Horarios.ID_Horario'), nullable=False)
    ID_Pasajero = db.Column(db.Integer, db.ForeignKey('Pasajeros.ID_Pasajero'), nullable=False)
    Numero_Asientos_Reservados = db.Column(db.Integer, nullable=False)
    Estado_Reserva = db.Column(db.String(20), nullable=False)
    Fecha_Reserva = db.Column(db.Date, nullable=False)

    def to_dict(self):
        return {
            'ID_Reserva': self.ID_Reserva,
            'ID_Horario': self.ID_Horario,
            'ID_Pasajero': self.ID_Pasajero,
            'Numero_Asientos_Reservados': self.Numero_Asientos_Reservados,
            'Estado_Reserva': self.Estado_Reserva,
            'Fecha_Reserva': str(self.Fecha_Reserva)
        }
#Ver reserva 
@app.route('/reservas', methods=['GET'])
@app.route('/reservas/<int:id>', methods=['GET'])
def get_reservas(id=None):
    if id:
        reserva = Reserva.query.get(id)
        if reserva:
            return jsonify(reserva.to_dict()), 200
        return jsonify({'error': 'Reserva no encontrada'}), 404
    else:
        reservas = Reserva.query.all()
        return jsonify([reserva.to_dict() for reserva in reservas]), 200
#Crear una Reserva
@app.route('/reservas', methods=['POST'])
def create_reserva():
    data = request.get_json()
    try:
        nueva_reserva = Reserva(
            ID_Horario=data['ID_Horario'],
            ID_Pasajero=data['ID_Pasajero'],
            Numero_Asientos_Reservados=data['Numero_Asientos_Reservados'],
            Estado_Reserva=data['Estado_Reserva'],
            Fecha_Reserva=datetime.strptime(data['Fecha_Reserva'], '%Y-%m-%d').date()
        )
        db.session.add(nueva_reserva)
        db.session.commit()
        return jsonify(nueva_reserva.to_dict()), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    db.create_all()
    app.run(port=5002, debug=True)
