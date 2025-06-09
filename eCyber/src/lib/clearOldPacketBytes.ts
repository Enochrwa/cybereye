// utils/clearOldPacketBytes.js
export function clearOldPacketBytes() {
    const today = new Date().toDateString();
    const savedDate = localStorage.getItem('packet_bytes_date');
  
    if (savedDate !== today) {
      localStorage.setItem('packet_bytes', '0');
      localStorage.setItem('packet_bytes_date', today);
    }
  }
  