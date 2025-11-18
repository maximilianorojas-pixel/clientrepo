const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Almacenamiento en memoria (en producción usar base de datos)
const clients = new Map();
const packages = new Map();

// Clave secreta para encriptación (en producción usar variables de entorno)
const SECRET_KEY = 'mi-clave-secreta-32-caracteres!!';

// Función para encriptar
function encrypt(text) {
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(SECRET_KEY), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Error encriptando:', error);
    return '';
  }
}

// Función para desencriptar
function decrypt(text) {
  try {
    const parts = text.split(':');
    if (parts.length !== 2) return '';
    
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = Buffer.from(parts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SECRET_KEY), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Error desencriptando:', error);
    return '';
  }
}

// Rutas del servidor web
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/clients', (req, res) => {
  const clientList = Array.from(clients.values()).map(client => ({
    id: client.id,
    name: client.name,
    ip: client.ip,
    os: client.os,
    lastSeen: client.lastSeen,
    status: client.status
  }));
  res.json(clientList);
});

app.post('/deploy-package', (req, res) => {
  try {
    const { clientId, packageName, packageType, installCommand, credentials } = req.body;
    
    if (!clientId || !packageName || !installCommand) {
      return res.status(400).json({ success: false, message: 'Datos incompletos' });
    }
    
    const packageData = {
      id: crypto.randomBytes(8).toString('hex'),
      name: packageName,
      type: packageType || 'custom',
      command: installCommand,
      credentials: encrypt(JSON.stringify(credentials || { user: 'SYSTEM', password: '' })),
      timestamp: new Date().toISOString()
    };
    
    packages.set(packageData.id, packageData);
    
    // Enviar paquete al cliente específico
    const client = clients.get(clientId);
    if (client && client.status === 'online') {
      // Crear un objeto limpio sin referencias circulares
      const cleanPackageData = {
        id: packageData.id,
        name: packageData.name,
        type: packageData.type,
        command: packageData.command,
        credentials: packageData.credentials,
        timestamp: packageData.timestamp
      };
      
      io.to(clientId).emit('install-package', cleanPackageData);
      res.json({ success: true, message: 'Paquete enviado al cliente', packageId: packageData.id });
    } else {
      res.status(404).json({ success: false, message: 'Cliente no encontrado o desconectado' });
    }
  } catch (error) {
    console.error('Error en deploy-package:', error);
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

// WebSocket connections
io.on('connection', (socket) => {
  console.log('Nuevo cliente conectado:', socket.id);
  
  socket.on('register-client', (clientData) => {
    try {
      console.log('Registrando cliente:', clientData);
      
      const clientInfo = {
        id: socket.id,
        name: clientData.name || 'Cliente Desconocido',
        ip: socket.handshake.address,
        os: clientData.os || 'Desconocido',
        lastSeen: new Date().toISOString(),
        status: 'online'
        // NOTA: No almacenamos el objeto socket para evitar referencias circulares
      };
      
      clients.set(socket.id, clientInfo);
      
      // Notificar a todos los administradores con datos limpios
      const cleanClients = Array.from(clients.values()).map(client => ({
        id: client.id,
        name: client.name,
        ip: client.ip,
        os: client.os,
        lastSeen: client.lastSeen,
        status: client.status
      }));
      
      io.emit('client-updated', cleanClients);
      
      console.log(`Cliente registrado: ${clientData.name} (${socket.id})`);
    } catch (error) {
      console.error('Error registrando cliente:', error);
    }
  });
  
  socket.on('installation-status', (statusData) => {
    try {
      console.log(`Estado de instalación: ${statusData.status} - ${statusData.message}`);
      
      // Notificar a los administradores
      io.emit('installation-update', {
        clientId: statusData.clientId,
        packageId: statusData.packageId,
        success: statusData.success,
        message: statusData.message,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error procesando estado de instalación:', error);
    }
  });
  
  socket.on('disconnect', (reason) => {
    try {
      console.log('Cliente desconectado:', socket.id, 'Razón:', reason);
      
      const client = clients.get(socket.id);
      if (client) {
        client.status = 'offline';
        client.lastSeen = new Date().toISOString();
        
        // Notificar a todos los administradores con datos limpios
        const cleanClients = Array.from(clients.values()).map(client => ({
          id: client.id,
          name: client.name,
          ip: client.ip,
          os: client.os,
          lastSeen: client.lastSeen,
          status: client.status
        }));
        
        io.emit('client-updated', cleanClients);
      }
    } catch (error) {
      console.error('Error en desconexión:', error);
    }
  });
  
  // Manejar errores
  socket.on('error', (error) => {
    console.error('Error en socket:', socket.id, error);
  });
});

// Manejo de errores global del servidor
server.on('error', (error) => {
  console.error('Error del servidor:', error);
});

process.on('uncaughtException', (error) => {
  console.error('Excepción no capturada:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Promesa rechazada no manejada:', reason);
});

server.listen(PORT, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});