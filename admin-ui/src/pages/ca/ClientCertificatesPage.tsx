import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Table, Button, Space, Typography, Tag, Modal, Input, Form, message, AutoComplete, Tooltip } from "antd";
import { DownloadOutlined, StopOutlined, PlusOutlined } from "@ant-design/icons";
import { listCertificates, listAuthorities, revokeCertificate, generateUserCert, downloadUserCert } from "../../api/ca";
import { Certificate } from "../../types/ca";
import { listUsers } from "../../api/users";

const { Title } = Typography;

export default function ClientCertificatesPage() {
  const queryClient = useQueryClient();
  const [downloadModalOpen, setDownloadModalOpen] = useState(false);
  const [generateModalOpen, setGenerateModalOpen] = useState(false);
  const [selectedCertId, setSelectedCertId] = useState<string | null>(null);
  const [form] = Form.useForm();
  const [userOptions, setUserOptions] = useState<{ value: string }[]>([]);

  const { data: authorities, isLoading: loadingAuth } = useQuery({
    queryKey: ["ca-authorities"],
    queryFn: listAuthorities,
  });

  const { data: certs, isLoading: loadingCerts } = useQuery({
    queryKey: ["ca-certificates"],
    queryFn: () => listCertificates(),
  });

  const revokeMutation = useMutation({
    mutationFn: revokeCertificate,
    onSuccess: () => {
      message.success("Certificate revoked");
      queryClient.invalidateQueries({ queryKey: ["ca-certificates"] });
    },
    onError: () => message.error("Failed to revoke certificate"),
  });

  const handleDownload = async (values: any) => {
    try {
      const blob = await downloadUserCert(selectedCertId!, values.bundlePassword);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `bundle.p12`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setDownloadModalOpen(false);
      form.resetFields();
    } catch (err) {
      message.error("Failed to download certificate bundle");
    }
  };

  const handleGenerate = async (values: any) => {
    try {
      const activeIntermediary = authorities?.items.find((c) => c.type === "intermediary" && !c.revoked_at);
      if (!activeIntermediary) {
        message.error("No active intermediary CA found");
        return;
      }

      await generateUserCert(values.username, activeIntermediary.id, values.interPassword);
      setGenerateModalOpen(false);
      form.resetFields();
      queryClient.invalidateQueries({ queryKey: ["ca-certificates"] });
      message.success("Certificate generated successfully");
    } catch (err: any) {
      const msg = err.response?.data?.error?.error_description || "Failed to generate certificate";
      message.error(msg);
    }
  };

  const handleUserSearch = async (value: string) => {
    if (!value) {
      setUserOptions([]);
      return;
    }
    try {
      const res = await listUsers({ search: value, limit: 10 });
      setUserOptions(res.items.map((u) => ({ value: u.username })));
    } catch {
      setUserOptions([]);
    }
  };

  const [, setFilters] = useState<Record<string, string[] | null>>({});

  const dataSource = useMemo(() => {
    return (certs?.items || []).filter(c => c.type === "user");
  }, [certs]);

  const uniqueUsers = useMemo(() => {
    const users = new Set(dataSource.map(d => d.username).filter((u): u is string => Boolean(u)));
    return Array.from(users).map(u => ({ text: u, value: u }));
  }, [dataSource]);

  const handleTableChange = (_: any, tableFilters: any) => {
    setFilters(tableFilters);
  };

  const columns = [
    {
      title: "User",
      dataIndex: "username",
      key: "username",
      filters: uniqueUsers,
      onFilter: (value: any, record: Certificate) => record.username === value,
    },
    {
      title: "Created At",
      dataIndex: "created_at",
      key: "created_at",
      render: (text: string) => new Date(text).toLocaleString(),
    },
    {
      title: "Expires At",
      dataIndex: "expire_date",
      key: "expire_date",
      render: (text: string) => text ? new Date(text).toLocaleString() : "-",
    },
    {
      title: "Status",
      key: "status",
      filters: [
        { text: "Active", value: "active" },
        { text: "Revoked", value: "revoked" },
      ],
      onFilter: (value: any, record: Certificate) => {
        if (value === "active") return !record.revoked_at;
        if (value === "revoked") return !!record.revoked_at;
        return true;
      },
      render: (_: any, record: Certificate) => (
        record.revoked_at ? <Tag color="red">Revoked</Tag> : <Tag color="green">Active</Tag>
      ),
    },
    {
      title: "Actions",
      key: "actions",
      render: (_: any, record: Certificate) => (
        <Space>
          <Tooltip title="Download">
            <Button
              type="text"
              size="small"
              icon={<DownloadOutlined />}
              disabled={!!record.revoked_at}
              onClick={() => {
                setSelectedCertId(record.id);
                setDownloadModalOpen(true);
              }}
            />
          </Tooltip>
          <Tooltip title="Revoke">
            <Button
              type="text"
              danger
              size="small"
              icon={<StopOutlined />}
              disabled={!!record.revoked_at}
              onClick={() => {
                Modal.confirm({
                  title: "Revoke Certificate?",
                  content: "Are you sure you want to revoke this certificate? This action cannot be undone.",
                  onOk: () => revokeMutation.mutate(record.id),
                });
              }}
            />
          </Tooltip>
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Title level={4} style={{ margin: 0 }}>Client Certificates</Title>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            form.resetFields();
            setGenerateModalOpen(true);
          }}
        >
          Generate User Certificate
        </Button>
      </div>

      <Table
        dataSource={dataSource}
        columns={columns}
        rowKey="id"
        loading={loadingCerts || loadingAuth}
        scroll={{ x: true }}
        onChange={handleTableChange}
      />

      <Modal
        title="Download Certificate Bundle"
        open={downloadModalOpen}
        onCancel={() => setDownloadModalOpen(false)}
        footer={null}
      >
        <Form form={form} layout="vertical" onFinish={handleDownload}>
          <Form.Item
            name="bundlePassword"
            label="Bundle Password"
            rules={[{ required: true, message: "Please enter the bundle password" }]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit">Download</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="Generate User Certificate"
        open={generateModalOpen}
        onCancel={() => setGenerateModalOpen(false)}
        footer={null}
      >
        <Form form={form} layout="vertical" onFinish={handleGenerate}>
          <Form.Item
            name="username"
            label="Username"
            rules={[{ required: true, message: "Please select a user" }]}
          >
            <AutoComplete
              options={userOptions}
              onSearch={handleUserSearch}
              placeholder="Search by username..."
            />
          </Form.Item>
          <Form.Item
            name="interPassword"
            label="Intermediary CA Password"
            rules={[{ required: true, message: "Please enter the Intermediary CA password" }]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit">Generate</Button>
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
