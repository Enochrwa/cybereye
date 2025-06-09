
import React from "react";
import DataTable from "./DataTable";
import { QuarantinedFile } from "@/types";

interface QuarantinedFilesTableProps {
  files: QuarantinedFile[];
  className?: string;
}

const QuarantinedFilesTable = ({ files, className }: QuarantinedFilesTableProps) => {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const columns = [
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (file: QuarantinedFile) => <span>{formatTimestamp(file.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "filePath",
      header: "File Path",
      cell: (file: QuarantinedFile) => (
        <span className="font-mono text-xs">{file.filePath}</span>
      ),
      sortable: true,
    },
    {
      key: "fileHash",
      header: "Hash",
      cell: (file: QuarantinedFile) => (
        <span className="font-mono text-xs truncate max-w-[120px] inline-block">{file.fileHash}</span>
      ),
    },
    {
      key: "reason",
      header: "Reason",
      cell: (file: QuarantinedFile) => (
        <span className="bg-threat-high/10 text-threat-high px-2 py-1 rounded text-xs">
          {file.reason}
        </span>
      ),
      sortable: true,
    },
    {
      key: "originalProcess",
      header: "Original Process",
      cell: (file: QuarantinedFile) => <span>{file.originalProcess}</span>,
      sortable: true,
    },
  ];

  return (
    <DataTable columns={columns} data={files} className={className} />
  );
};

export default QuarantinedFilesTable;
