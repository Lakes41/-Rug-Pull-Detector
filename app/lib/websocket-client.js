/**
 * WebSocket client for real-time alert subscriptions
 * Connects to the Rust WebSocket server for live anomaly alerts
 */

class AlertWebSocket {
  constructor(url = 'ws://127.0.0.1:8080') {
    this.url = url;
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;
    this.listeners = new Map();
    this.subscriptions = new Set();
    this.connected = false;
  }

  /**
   * Connect to the WebSocket server
   */
  connect() {
    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.connected = true;
        this.reconnectAttempts = 0;
        this.emit('connected');
        
        // Resubscribe to previous subscriptions after reconnection
        this.subscriptions.forEach(address => {
          this.subscribe(address);
        });
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.handleMessage(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.connected = false;
        this.emit('disconnected');
        this.attemptReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.emit('error', error);
      };
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      this.attemptReconnect();
    }
  }

  /**
   * Attempt to reconnect to the server
   */
  attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * this.reconnectAttempts;
      console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
      
      setTimeout(() => {
        this.connect();
      }, delay);
    } else {
      console.error('Max reconnection attempts reached');
      this.emit('maxReconnectAttemptsReached');
    }
  }

  /**
   * Handle incoming messages from the server
   */
  handleMessage(message) {
    switch (message.message) {
      case 'alert':
        this.emit('alert', message);
        break;
      case 'subscribed':
        console.log(`Subscribed to ${message.address}`);
        this.emit('subscribed', message);
        break;
      case 'unsubscribed':
        console.log(`Unsubscribed from ${message.address}`);
        this.emit('unsubscribed', message);
        break;
      case 'error':
        console.error('Server error:', message.error);
        this.emit('serverError', message);
        break;
      default:
        console.warn('Unknown message type:', message);
    }
  }

  /**
   * Subscribe to alerts for a specific smart contract address
   */
  subscribe(address) {
    if (!this.connected) {
      console.warn('WebSocket not connected, subscription queued');
      this.subscriptions.add(address);
      return;
    }

    const message = {
      action: 'subscribe',
      address: address.toLowerCase()
    };

    this.ws.send(JSON.stringify(message));
    this.subscriptions.add(address);
  }

  /**
   * Unsubscribe from alerts for a specific smart contract address
   */
  unsubscribe(address) {
    if (!this.connected) {
      this.subscriptions.delete(address);
      return;
    }

    const message = {
      action: 'unsubscribe',
      address: address.toLowerCase()
    };

    this.ws.send(JSON.stringify(message));
    this.subscriptions.delete(address);
  }

  /**
   * Register an event listener
   */
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event).push(callback);
  }

  /**
   * Remove an event listener
   */
  off(event, callback) {
    if (this.listeners.has(event)) {
      const callbacks = this.listeners.get(event);
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  /**
   * Emit an event to all registered listeners
   */
  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`Error in ${event} listener:`, error);
        }
      });
    }
  }

  /**
   * Disconnect from the WebSocket server
   */
  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
      this.connected = false;
      this.subscriptions.clear();
    }
  }

  /**
   * Check if the WebSocket is connected
   */
  isConnected() {
    return this.connected;
  }
}

// Export singleton instance
export const alertWebSocket = new AlertWebSocket();

// Export class for custom instances
export default AlertWebSocket;
