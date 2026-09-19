import React from 'react';
import { EmptyState } from './EmptyState';
import { SkeletonTable } from './Skeleton';

interface Column<T> {
  key: string;
  label: string;
  render: (row: T) => React.ReactNode;
  className?: string;
  headerClassName?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[] | null;
  keyField: (row: T) => string;
  empty?: { title: string; description?: string; action?: React.ReactNode };
  loading?: boolean;
  error?: string;
  onRowClick?: (row: T) => void;
  onRetry?: () => void;
}

export const DataTable = <T,>({
  columns,
  rows,
  keyField,
  empty,
  loading,
  error,
  onRowClick,
  onRetry,
}: DataTableProps<T>): React.ReactElement => {
  if (error) {
    return (
      <div className="text-[12px] text-critical py-8 text-center border border-critical/30 bg-critical/5 rounded-md">
        {error}
      </div>
    );
  }

  if (loading || rows === null) {
    return <SkeletonTable rows={4} cols={columns.length} />;
  }

  if (rows.length === 0) {
    return empty ? (
      <EmptyState
        title={empty.title}
        description={empty.description}
        action={empty.action}
      />
    ) : (
      <div className="text-center text-muted text-[12.5px] py-10">No records.</div>
    );
  }

  return (
    <div className="border border-line rounded-md overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse tbl">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={c.headerClassName}>
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={keyField(row)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={onRowClick ? 'cursor-pointer' : ''}
              >
                {columns.map((c) => (
                  <td key={c.key} className={c.className}>
                    {c.render(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};