import React, { useState } from 'react';
import { Play, X } from 'lucide-react';

const DemoVideo = ({ isVideoOpen, setIsVideoOpen}) => {
 
  const embedUrl = 'https://www.youtube.com/embed/3bqPM6-cmuE?autoplay=1&rel=0&modestbranding=1';

  return (
    <div className="text-center p-8">
      {/* Watch Button */}
     

      {/* Modal */}
      {isVideoOpen && (
        <div 
          className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4
                     animate-in fade-in duration-300"
          onClick={() => setIsVideoOpen(false)}
        >
          <div 
            className="relative w-full max-w-5xl aspect-video bg-black rounded-2xl overflow-hidden 
                       shadow-2xl border border-white/10 animate-in zoom-in-95 duration-300"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Close Button */}
            <button
              onClick={() => setIsVideoOpen(false)}
              className="absolute top-4 right-4 z-50 text-white/80 hover:text-white 
                         bg-black/50 hover:bg-black/70 backdrop-blur-sm rounded-full 
                         w-10 h-10 flex items-center justify-center transition-all duration-200
                         hover:scale-110"
            >
              <X className="w-5 h-5" />
            </button>

            {/* YouTube iframe */}
            <iframe
              className="w-full h-full"
              src={embedUrl}
              title="Demo Video"
              frameBorder="0"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
              allowFullScreen
            />
          </div>
        </div>
      )}
    </div>
  )
};

export default DemoVideo;