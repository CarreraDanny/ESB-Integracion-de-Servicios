#Librerías
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import requests
import logging
import xmltodict
import pyodbc
from functools import wraps
import jwt  # Asegúrate de que esta es la biblioteca pyjwt
from jwt import ExpiredSignatureError, InvalidTokenError  # Importa las excepciones aquí
from datetime import datetime, timedelta
from esb.services.service_reservas import Reserva

# Importa la función de conexión
from conexionlog import get_sqlserver_connection
#Inicio Programa
app = Flask(__name__)
app.secret_key = 'loki123'

# Configuración de Flask-JWT-Extended
app.config['JWT_SECRET_KEY'] = 'danny123'  # Cambia esto por una clave secreta más segura
# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Configuración de Flask-JWT-Extended
jwt_manager = JWTManager(app)
#Ruta
#Página Principal
#================================================================
# Token => Autenticación
# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')

        if not token:
            return redirect(url_for('login'))

        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            session['user_id'] = data['sub']['user_id']
            session['user_name'] = data['sub']['user_name']
            session['user_role'] = data['sub']['user_role']
        except ExpiredSignatureError:
            session.clear()  # Limpiar toda la sesión
            return redirect(url_for('login'))
        except InvalidTokenError:
            session.clear()  # Limpiar toda la sesión
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated

@app.before_request
def clear_invalid_token():
    token = session.get('token')
    if token:
        try:
            jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        except (ExpiredSignatureError, InvalidTokenError):
            session.clear()  # Limpiar toda la sesión si el token es inválido o ha expirado


#===============================================================================================
#Ruta Inicial
@app.route('/')
@token_required
def home():
    if 'user_role' in session:
        if session['user_role'] == 'Cliente':
            return render_template('index.html')
        else:
            return "Acceso denegado. No tienes permiso para acceder a esta página."
    return redirect(url_for('login'))

# Página para Ver Rutas desde Csharp#
@app.route('/ver_rutas_csharp')
def ver_rutas_csharp():
    return render_template('VerRutasCSharp.html')
# Página para Ver Rutas desde Python
@app.route('/ver_rutas_python')
def ver_rutas_python():
    return render_template('VerRutasPython.html')
# Página para Ver todas las  Rutas disponibles
@app.route('/ver_rutas')
@token_required
def ver_rutas():
    return render_template('VerRutas.html')
# Página para Ver Reservas
@app.route('/ver_reservas')
@token_required
def ver_reservas():
    return render_template('VerReservas.html')
# Página para Crear Reserva=> Python
@app.route('/crear_reserva')
@token_required
def crear_reserva():
    return render_template('CrearReserva.html')
#Ver reservas c-sharp
@app.route('/ver_reservas_csharp')
@token_required
def ver_reservas_csharp():
    return render_template('ver_reservas_csharp.html')
#Ver Reservas Python
@app.route('/ver_reservas_python')
@token_required
def ver_reservas_python():
    return render_template('ver_reservas_python.html')
# Renderizar formulario para crear reserva en C#
@app.route('/form_crear_reserva_csharp')
@token_required
def form_crear_reserva_csharp():
    return render_template('crear_reserva_csharp.html')
# Renderizar formulario para crear reserva en C#
@app.route('/unidades')
@token_required
def unidades():
    return render_template('Unidades.html')
# Renderizar la página de horarios desde el servicio C#
@app.route('/ver_horarios_csharp')
@token_required
def ver_horarios_csharp():
    return render_template('ver_horarios_csharp.html')
# Renderizar la página de horarios desde el servicio Python
@app.route('/ver_horarios_python')
@token_required
def ver_horarios_python():
    return render_template('ver_horarios_python.html')
# Página para Ver Reservas
@app.route('/ver_horarios')
@token_required
def ver_horarios():
    return render_template('ver_horarios.html')
#=========================================> Servicio Felipe<==========================================
#======================================================================================================
#Metodo GET Y POST  servicio Felipe
@app.route('/ver_rutas_felipe')
@token_required
def ver_rutas_felipe():
    return render_template('ver_rutas_felipe.html')
#Ver Reservas Felipe
@app.route('/ver_reservas_felipe')
@token_required
def ver_reservas_felipe():
    return render_template('ver_reservas_felipe.html')
#Crear Reserva Felipe
@app.route('/form_crear_reserva_felipe')
@token_required
def form_crear_reserva_felipe():
    return render_template('crear_reserva_felipe.html')
#Ver Horarios
@app.route('/ver_horarios_felipe')
@token_required
def ver_horarios_felipe():
    return render_template('ver_horarios_felipe.html')

#============================================Servicio de Python Danny==================================
#==================================================>Rutas<================================
#Ver Rutas
@app.route('/rutas', methods=['GET'])
@app.route('/rutas/<int:id>', methods=['GET'])
def rutas(id=None):
    try:
        service_url = f'http://127.0.0.1:5000/rutas'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500
#====================================>Reservas<=================================================
#Crear Reserva y ver Reserva
#=====================================
# Ver Reservas
@app.route('/reservas', methods=['GET'])
@app.route('/reservas/<int:id>', methods=['GET'])
def reservas(id=None):
    try:
        service_url = f'http://127.0.0.1:5000/reservas'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# Crear Reserva
@app.route('/crear_reserva', methods=['POST'])
def post_reserva():
    try:
        service_url = f'http://127.0.0.1:5000/reservas'
        response = requests.post(service_url, json=request.json)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500
#Horarios
# ==================================> Horarios <================================
# Ver Horarios
@app.route('/horarios', methods=['GET'])
@app.route('/horarios/<int:id>', methods=['GET'])
def get_horarios(id=None):
    try:
        service_url = f'http://127.0.0.1:5000/horarios'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Crear Horario
@app.route('/crear_horario', methods=['POST'])
def post_horario():
    try:
        service_url = f'http://127.0.0.1:5000/horarios'
        response = requests.post(service_url, json=request.json)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#=======================>CSHARP-SERVICIOS<===================================================
# ==================================> C# API Rutas <================================
#API C# => Cristhian Servicio 
# Ver Rutas desde la API C#
@app.route('/csharp_rutas', methods=['GET'])
@app.route('/csharp_rutas/<int:id>', methods=['GET'])
def csharp_rutas(id=None):
    try:
        service_url = f'http://localhost:60284/api/RUTAS'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        logger.info(f"Response from C# service: {response.content}")
        if response.headers['Content-Type'] == 'application/xml':
            data = xmltodict.parse(response.content)
            logger.info(f"Parsed XML data: {data}")
            return jsonify(data), response.status_code
        else:
            return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error fetching data from C# service: {str(e)}")
        return jsonify({'error': str(e)}), 500
#Ver Reservas
# Ver Reservas desde la API C# => Cristhian Servicio 
@app.route('/csharp_reservas', methods=['GET'])
@app.route('/csharp_reservas/<int:id>', methods=['GET'])
def csharp_reservas(id=None):
    try:
        service_url = f'http://localhost:60284/api/Reservas'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        logger.info(f"Response from C# service: {response.content}")
        if response.headers['Content-Type'] == 'application/xml':
            data = xmltodict.parse(response.content)
            logger.info(f"Parsed XML data: {data}")
            return jsonify(data), response.status_code
        else:
            return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error fetching data from C# service: {str(e)}")
        return jsonify({'error': str(e)}), 500
# Crear Reserva en el servicio C#
@app.route('/crear_reserva_csharp', methods=['POST'])
def crear_reserva_csharp():
    try:
        data = request.get_json()
        service_url = 'http://localhost:60284/api/Reservas'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(service_url, json=data, headers=headers)
        
        if response.status_code == 201:
            return jsonify({'message': 'Reserva creada exitosamente'}), 201
        else:
            return jsonify({'error': response.json()}), response.status_code
    except Exception as e:
        logger.error(f"Error creando reserva en el servicio C#: {str(e)}")
        return jsonify({'error': str(e)}), 500
# Ver Horarios desde la API C#
@app.route('/csharp_horarios', methods=['GET'])
@app.route('/csharp_horarios/<int:id>', methods=['GET'])
def csharp_horarios(id=None):
    try:
        service_url = f'http://localhost:60284/api/Horarios'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        logger.info(f"Response from C# service: {response.content}")
        if response.headers['Content-Type'] == 'application/xml':
            data = xmltodict.parse(response.content)
            logger.info(f"Parsed XML data: {data}")
            return jsonify(data), response.status_code
        else:
            return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error fetching data from C# service: {str(e)}")
        return jsonify({'error': str(e)}), 500
#=====================================================================================================   
#Csharp SERVICIO Felipe
# Ver Rutas desde la nueva API C#
@app.route('/csharpfelipe', methods=['GET'])
@app.route('/csharpfelipe/<int:id>', methods=['GET'])
def new_csharp_rutas(id=None):
    try:
        service_url = f'http://localhost:50202/api/Rutas'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        logger.info(f"Response from new C# service: {response.content}")
        if response.headers['Content-Type'] == 'application/xml':
            data = xmltodict.parse(response.content)
            logger.info(f"Parsed XML data: {data}")
            return jsonify(data), response.status_code
        else:
            return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error fetching data from new C# service: {str(e)}")
        return jsonify({'error': str(e)}), 500
#Ver Reservas desde API Felipe 
@app.route('/csharpfelipereservas', methods=['GET'])
@app.route('/csharpfelipereservas/<int:id>', methods=['GET'])
def new_csharp_reservas(id=None):
    try:
        service_url = f'http://localhost:50202/api/Reservas'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        logger.info(f"Response from new C# reservations service: {response.content}")
        if response.headers['Content-Type'] == 'application/xml':
            data = xmltodict.parse(response.content)
            logger.info(f"Parsed XML data: {data}")
            return jsonify(data), response.status_code
        else:
            return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error fetching data from new C# reservations service: {str(e)}")
        return jsonify({'error': str(e)}), 500
#Crear Reservas desde API Felipe
# Crear Reserva en el nuevo servicio C#
@app.route('/crear_reserva_felipe', methods=['POST'])
def crear_reserva_felipe():
    try:
        data = request.get_json()
        service_url = 'http://localhost:50202/api/Reservas'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(service_url, json=data, headers=headers)
        
        if response.status_code == 201:
            return jsonify({'message': 'Reserva creada exitosamente'}), 201
        else:
            return jsonify({'error': response.json()}), response.status_code
    except Exception as e:
        logger.error(f"Error creando reserva en el nuevo servicio C#: {str(e)}")
        return jsonify({'error': str(e)}), 500

#Ver Horarios Felipe
# Ver Horarios desde el nuevo servicio C#
@app.route('/felipe_horarios', methods=['GET'])
@app.route('/felipe_horarios/<int:id>', methods=['GET'])
def felipe_horarios(id=None):
    try:
        service_url = f'http://localhost:50202/api/Horarios'
        if id:
            service_url += f'/{id}'
        response = requests.get(service_url)
        logger.info(f"Response from Felipe's service: {response.content}")
        if response.headers['Content-Type'] == 'application/xml':
            data = xmltodict.parse(response.content)
            logger.info(f"Parsed XML data: {data}")
            return jsonify(data), response.status_code
        else:
            return jsonify(response.json()), response.status_code
    except Exception as e:
        logger.error(f"Error fetching data from Felipe's service: {str(e)}")
        return jsonify({'error': str(e)}), 500


#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#=====================================================================================================
#Login=> BD Utilizada=> SQL SERVER=> Tabla Usuarios
#=====================================================================================================
# Ruta para el registro de usuarios
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        correo = request.form['correo']
        contrasena = request.form['contrasena']
        rol = request.form['rol']

        connection = get_sqlserver_connection()
        cursor = connection.cursor()

        cursor.execute('SELECT * FROM Usuarios WHERE USCORREO = ?', (correo,))
        user = cursor.fetchone()
        if user:
            error = 'El correo ya está registrado'
            return render_template('registro.html', error=error)

        cursor.execute('''
            INSERT INTO Usuarios (USNOMBRE, USAPELLIDO, USCORREO, USCONTRASENA, ROL)
            VALUES (?, ?, ?, ?, ?)
        ''', (nombre, apellido, correo, contrasena, rol))

        connection.commit()
        connection.close()

        success = 'Registro exitoso. Por favor, inicie sesión.'
        return render_template('registro.html', success=success)

    return render_template('registro.html')

#==========================================================================================
# Verificar credenciales y generar token al iniciar sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_sqlserver_connection()
        cursor = connection.cursor()
        cursor.execute('SELECT IDUSUARIO, USNOMBRE, USAPELLIDO, USCORREO, USCONTRASENA,ROL FROM Usuarios WHERE USCORREO = ?', (email,))
        user = cursor.fetchone()

        if user and user.USCONTRASENA == password:
            access_token = create_access_token(identity={
                'user_id': user.IDUSUARIO,
                'user_name': user.USNOMBRE,
                'user_role': user.ROL
            })
            session['token'] = access_token
            return redirect(url_for('home'))
        else:
            error = 'Credenciales incorrectas'
            return render_template('login.html', error=error)

    return render_template('login.html')
#Ruta cerrar Sesión => Cerrar Token
# Cerrar Sesión
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(port=5001, debug=True)