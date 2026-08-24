import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { IconChevronRight } from '@tabler/icons-react';
import api from '../api';
import Card from '../components/Card';
import Button from '../components/Button';
import StatusDot from '../components/StatusDot';
import { cn } from '../lib/utils';

interface ApplicationNode {
  name: string;
  description?: string;
  icon?: string;
  url?: string;
  groups?: string[];
  items?: ApplicationNode[];
}

const Dashboard: React.FC = () => {
  const { data: profile } = useQuery({
    queryKey: ['profile'],
    queryFn: () => api.get('/profile').then((res) => res.data.data),
  });
  const { data: mfa } = useQuery({
    queryKey: ['mfa'],
    queryFn: () => api.get('/mfa').then((res) => res.data.data),
  });
  const { data: apps = [] } = useQuery({
    queryKey: ['applications'],
    queryFn: () => api.get('/applications').then((res) => res.data.data as ApplicationNode[]),
  });

  return (
    <div className="space-y-4" data-testid="account-dashboard">
      {apps && apps.length > 0 && (
        <Card title="Applications">
          <div className="mt-2 flex flex-col gap-6">
            {(() => {
              // We need to group contiguous standalone apps into a single grid.
              const blocks: any[] = [];
              let currentStandaloneGroup: ApplicationNode[] = [];

              apps.forEach((node, idx) => {
                if (node.items) {
                  if (currentStandaloneGroup.length > 0) {
                    blocks.push({ type: 'standalone-group', items: currentStandaloneGroup, id: `sg-${idx}` });
                    currentStandaloneGroup = [];
                  }
                  blocks.push({ type: 'category', node, id: `cat-${idx}` });
                } else {
                  currentStandaloneGroup.push(node);
                }
              });
              if (currentStandaloneGroup.length > 0) {
                blocks.push({ type: 'standalone-group', items: currentStandaloneGroup, id: 'sg-last' });
              }

              return blocks.map((block) => {
                if (block.type === 'category') {
                  const node = block.node;
                  return (
                    <div key={block.id} className="space-y-2">
                      {node.name && <h3 className="text-sm font-semibold text-theme-muted">{node.name}</h3>}
                      {!node.name && <div className="h-2"></div> /* Spacer */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                        {node.items.map((app: any, j: number) => (
                          <a
                            key={j}
                            href={app.url}
                            target="_blank"
                            rel="noreferrer"
                            className="flex items-center gap-3 p-3 rounded-lg border border-theme-fg/10 hover:bg-theme-fg/5 transition-colors"
                          >
                            {app.icon ? (
                              <img src={app.icon} alt={app.name} className="w-8 h-8 object-contain rounded" />
                            ) : (
                              <div className="w-8 h-8 rounded bg-theme-fg/10 flex items-center justify-center text-sm font-semibold">
                                {app.name.charAt(0).toUpperCase()}
                              </div>
                            )}
                            <div className="flex flex-col overflow-hidden">
                              <span className="font-medium text-sm truncate">{app.name}</span>
                              {app.description && <span className="text-xs text-theme-muted truncate">{app.description}</span>}
                            </div>
                          </a>
                        ))}
                      </div>
                    </div>
                  );
                } else {
                  // standalone-group
                  return (
                    <div key={block.id} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                      {block.items.map((node: any, j: number) => (
                        <a
                          key={j}
                          href={node.url}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-3 p-3 rounded-lg border border-theme-fg/10 hover:bg-theme-fg/5 transition-colors"
                        >
                          {node.icon ? (
                            <img src={node.icon} alt={node.name} className="w-8 h-8 object-contain rounded" />
                          ) : (
                            <div className="w-8 h-8 rounded bg-theme-fg/10 flex items-center justify-center text-sm font-semibold">
                              {node.name.charAt(0).toUpperCase()}
                            </div>
                          )}
                          <div className="flex flex-col overflow-hidden">
                            <span className="font-medium text-sm truncate">{node.name}</span>
                            {node.description && <span className="text-xs text-theme-muted truncate">{node.description}</span>}
                          </div>
                        </a>
                      ))}
                    </div>
                  );
                }
              });
            })()}
          </div>
        </Card>
      )}

      <Card
        title="Account Security"
        action={
          <Link to="/security">
            <Button variant="primary">
              Manage <IconChevronRight size={13} />
            </Button>
          </Link>
        }
      >
        <div className="flex items-center gap-2 mt-1">
          <StatusDot active={!!mfa?.totp_enabled} />
          <span className="text-sm">
            Two-factor authentication{' '}
            <span className={cn('font-semibold', mfa?.totp_enabled ? 'text-theme-success' : 'text-theme-muted')}>
              {mfa?.totp_enabled ? 'enabled' : 'not configured'}
            </span>
          </span>
        </div>
      </Card>

      <Card
        title="Profile"
        action={
          <Link to="/profile">
            <Button variant="primary">
              Update <IconChevronRight size={13} />
            </Button>
          </Link>
        }
      >
        <dl className="space-y-3 mt-1">
          {[
            { label: 'Username', value: profile?.username },
            { label: 'Email', value: profile?.email || '—' },
          ].map((row) => (
            <div key={row.label} className="flex justify-between items-center">
              <dt className="text-sm text-theme-muted">{row.label}</dt>
              <dd className="text-sm font-semibold">{row.value}</dd>
            </div>
          ))}
        </dl>
      </Card>
    </div>
  );
};

export default Dashboard;
