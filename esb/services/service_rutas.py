from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:12345@localhost/transporte'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Ruta(db.Model):
    __tablename__ = 'Rutas'
    ID_Ruta = db.Column(db.Integer, primary_key=True)
    Origen = db.Column(db.String(100), nullable=False)
    Destino = db.Column(db.String(100), nullable=False)
    Distancia = db.Column(db.Numeric(10, 2), nullable=False)
    Duracion_Estimada = db.Column(db.Time, nullable=False)

    def to_dict(self):
        return {
            'ID_Ruta': self.ID_Ruta,
            'Origen': self.Origen,
            'Destino': self.Destino,
            'Distancia': float(self.Distancia),
            'Duracion_Estimada': str(self.Duracion_Estimada)
        }

@app.route('/rutas', methods=['GET'])
@app.route('/rutas/<int:id>', methods=['GET'])
def get_rutas(id=None):
    if id:
        ruta = Ruta.query.get(id)
        if ruta:
            return jsonify(ruta.to_dict()), 200
        return jsonify({'error': 'Ruta not found'}), 404
    else:
        rutas = Ruta.query.all()
        return jsonify([ruta.to_dict() for ruta in rutas]), 200

if __name__ == '__main__':
    db.create_all()
    app.run(port=5001, debug=True)
