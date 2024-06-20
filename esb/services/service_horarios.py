from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:12345@localhost/transporte'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Horario(db.Model):
    __tablename__ = 'Horarios'
    ID_Horario = db.Column(db.Integer, primary_key=True)
    ID_Ruta = db.Column(db.Integer, db.ForeignKey('Rutas.ID_Ruta'), nullable=False)
    ID_Bus = db.Column(db.Integer, db.ForeignKey('Buses.ID_Bus'), nullable=False)
    ID_Conductor = db.Column(db.Integer, db.ForeignKey('Conductores.ID_Conductor'), nullable=False)
    Dia_Semana = db.Column(db.String(20), nullable=False)
    Hora_Salida = db.Column(db.Time, nullable=False)
    Hora_Llegada = db.Column(db.Time, nullable=False)

    def to_dict(self):
        return {
            'ID_Horario': self.ID_Horario,
            'ID_Ruta': self.ID_Ruta,
            'ID_Bus': self.ID_Bus,
            'ID_Conductor': self.ID_Conductor,
            'Dia_Semana': self.Dia_Semana,
            'Hora_Salida': str(self.Hora_Salida),
            'Hora_Llegada': str(self.Hora_Llegada)
        }

# Ver horarios
@app.route('/horarios', methods=['GET'])
@app.route('/horarios/<int:id>', methods=['GET'])
def get_horarios(id=None):
    if id:
        horario = Horario.query.get(id)
        if horario:
            return jsonify(horario.to_dict()), 200
        return jsonify({'error': 'Horario no encontrado'}), 404
    else:
        horarios = Horario.query.all()
        return jsonify([horario.to_dict() for horario in horarios]), 200

# Crear un horario
@app.route('/horarios', methods=['POST'])
def create_horario():
    data = request.get_json()
    try:
        nuevo_horario = Horario(
            ID_Ruta=data['ID_Ruta'],
            ID_Bus=data['ID_Bus'],
            ID_Conductor=data['ID_Conductor'],
            Dia_Semana=data['Dia_Semana'],
            Hora_Salida=datetime.strptime(data['Hora_Salida'], '%H:%M:%S').time(),
            Hora_Llegada=datetime.strptime(data['Hora_Llegada'], '%H:%M:%S').time()
        )
        db.session.add(nuevo_horario)
        db.session.commit()
        return jsonify(nuevo_horario.to_dict()), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    db.create_all()
    app.run(port=5003, debug=True)
