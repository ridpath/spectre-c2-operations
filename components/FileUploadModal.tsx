import React, { useState, useRef } from 'react';
import { Upload, X, File, CheckCircle, AlertCircle } from 'lucide-react';
import { authService } from '../services/authService';

interface FileUploadModalProps {
  type: 'evidence' | 'iq';
  missionId?: string;
  onClose: () => void;
  onUploadComplete?: () => void;
}

const FileUploadModal: React.FC<FileUploadModalProps> = ({ type, missionId, onClose, onUploadComplete }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [description, setDescription] = useState('');
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStatus, setUploadStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const maxSize = 1024 * 1024 * 1024;
      if (file.size > maxSize) {
        setErrorMessage('File size exceeds 1GB limit');
        setUploadStatus('error');
        return;
      }
      setSelectedFile(file);
      setUploadStatus('idle');
      setErrorMessage('');
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    if (type === 'evidence' && !missionId) {
      setErrorMessage('Mission ID is required for evidence upload');
      setUploadStatus('error');
      return;
    }

    setUploading(true);
    setUploadProgress(0);
    setUploadStatus('idle');

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      
      if (type === 'evidence') {
        formData.append('mission_id', missionId!);
        if (description) {
          formData.append('description', description);
        }
      } else {
        formData.append('sample_rate', '2400000');
        formData.append('center_frequency', '437500000');
        if (description) {
          formData.append('description', description);
        }
      }

      const endpoint = type === 'evidence' 
        ? 'http://localhost:8000/api/v1/evidence/upload'
        : 'http://localhost:8000/api/v1/iq/upload';

      const token = authService.getAccessToken();
      
      const xhr = new XMLHttpRequest();
      
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const progress = Math.round((e.loaded / e.total) * 100);
          setUploadProgress(progress);
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status === 200) {
          setUploadStatus('success');
          setUploading(false);
          setTimeout(() => {
            onUploadComplete?.();
            onClose();
          }, 1500);
        } else {
          setUploadStatus('error');
          setErrorMessage(xhr.responseText || 'Upload failed');
          setUploading(false);
        }
      });

      xhr.addEventListener('error', () => {
        setUploadStatus('error');
        setErrorMessage('Network error occurred');
        setUploading(false);
      });

      xhr.open('POST', endpoint);
      if (token) {
        xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      }
      xhr.send(formData);
    } catch (error: any) {
      setUploadStatus('error');
      setErrorMessage(error.message || 'Upload failed');
      setUploading(false);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-6">
      <div className="bg-[#0b1120] border border-white/10 rounded-2xl p-8 max-w-2xl w-full shadow-2xl">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="text-xl font-black text-white uppercase tracking-tight">
              {type === 'evidence' ? 'Upload Evidence File' : 'Upload IQ Recording'}
            </h2>
            <p className="text-xs text-slate-500 font-mono mt-1">Max file size: 1GB</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 bg-slate-800 rounded-xl text-slate-400 hover:text-white border border-white/5 transition-all"
          >
            <X size={20} />
          </button>
        </div>

        <div className="space-y-6">
          <div
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-slate-700 hover:border-emerald-500/50 rounded-xl p-12 text-center cursor-pointer transition-all bg-black/40"
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileSelect}
              className="hidden"
              accept={type === 'iq' ? '.iq,.raw,.bin,.dat,.cf32,.cf64' : '*'}
            />
            
            {selectedFile ? (
              <div className="flex items-center justify-center gap-4">
                <File className="text-emerald-500" size={32} />
                <div className="text-left">
                  <p className="text-white font-mono text-sm">{selectedFile.name}</p>
                  <p className="text-slate-500 text-xs">{formatFileSize(selectedFile.size)}</p>
                </div>
              </div>
            ) : (
              <div>
                <Upload className="mx-auto mb-4 text-slate-600" size={48} />
                <p className="text-slate-400 font-mono text-sm">Click to select file</p>
                <p className="text-slate-600 text-xs mt-2">
                  {type === 'iq' ? 'IQ files (.iq, .raw, .bin, .dat)' : 'Any file type supported'}
                </p>
              </div>
            )}
          </div>

          <div className="space-y-2">
            <label className="text-xs font-black text-slate-500 uppercase tracking-widest">
              Description (Optional)
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-black/60 border border-slate-800 rounded-xl p-4 text-sm font-mono text-emerald-400 focus:border-emerald-500 transition-all outline-none resize-none"
              rows={3}
              placeholder={type === 'evidence' ? 'Evidence description...' : 'Recording description...'}
            />
          </div>

          {uploading && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Uploading...</span>
                <span className="text-emerald-500">{uploadProgress}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-emerald-500 h-full transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}

          {uploadStatus === 'success' && (
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 flex items-center gap-3">
              <CheckCircle className="text-emerald-500" size={20} />
              <span className="text-emerald-400 text-sm font-mono">Upload successful!</span>
            </div>
          )}

          {uploadStatus === 'error' && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-start gap-3">
              <AlertCircle className="text-red-500 mt-0.5" size={20} />
              <div>
                <p className="text-red-400 text-sm font-mono">Upload failed</p>
                {errorMessage && (
                  <p className="text-red-500/70 text-xs font-mono mt-1">{errorMessage}</p>
                )}
              </div>
            </div>
          )}

          <div className="flex gap-4 pt-4">
            <button
              onClick={handleUpload}
              disabled={!selectedFile || uploading || uploadStatus === 'success'}
              className="flex-1 py-4 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-30 disabled:cursor-not-allowed text-white rounded-xl text-xs font-black uppercase tracking-widest transition-all flex items-center justify-center gap-2"
            >
              <Upload size={16} />
              {uploading ? 'Uploading...' : uploadStatus === 'success' ? 'Uploaded' : 'Upload File'}
            </button>
            <button
              onClick={onClose}
              className="px-6 py-4 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white rounded-xl text-xs font-black uppercase tracking-widest transition-all"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FileUploadModal;
