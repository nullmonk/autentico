import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Table, Button, Space, Typography, Tag, Modal, Form, message, Tooltip, Select } from "antd";
import { StopOutlined, PlusOutlined } from "@ant-design/icons";
import { listCertificates, listAuthorities, revokeCertificate, generateServerCert } from "../../api/ca";
import { Certificate } from "../../types/ca";

const { Title } = Typography;

export default function ServerCertificatesPage() {
  const queryClient = useQueryClient();
  const [generateModalOpen, setGenerateModalOpen] = useState(false);
  const [form] = Form.useForm();

  const { data: authorities, isLoading: loadingAuth } = useQuery({
    queryKey: ["ca-authorities"],
    queryFn: listAuthorities,
  });

  const { data: certs, isLoading: loadingCerts } = useQuery({
    queryKey: ["ca-certificates", "server"],
    queryFn: () => listCertificates(undefined, "server"),
  });

  const revokeMutation = useMutation({
    mutationFn: revokeCertificate,
    onSuccess: () => {
      message.success("Certificate revoked");
      queryClient.invalidateQueries({ queryKey: ["ca-certificates"] });
    },
    onError: () => message.error("Failed to revoke certificate"),
  });

  const handleGenerate = async (values: any) => {
    try {
      const activeIntermediary = authorities?.items.find((c) => c.type === "server-int" && !c.revoked_at);
      if (!activeIntermediary) {
        message.error("No active server intermediary CA found");
        return;
      }

      await generateServerCert(values.hosts, activeIntermediary.id, ""); // Backend manages server inter password
      setGenerateModalOpen(false);
      form.resetFields();
      queryClient.invalidateQueries({ queryKey: ["ca-certificates"] });
      message.success("Certificate generated successfully");
    } catch (err: any) {
      const msg = err.response?.data?.error?.error_description || "Failed to generate certificate";
      message.error(msg);
    }
  };

  const dataSource = useMemo(() => {
    return (certs?.items || []).filter(c => c.type === "server");
  }, [certs]);

  const columns = [
    {
      title: "Common Name (CN)",
      dataIndex: "cn",
      key: "cn",
      render: (text: string) => text || "-",
    },
    {
      title: "Hosts (SANs)",
      dataIndex: "hosts",
      key: "hosts",
      render: (text: string) => {
        try {
          const hosts = JSON.parse(text);
          return Array.isArray(hosts) ? hosts.join(", ") : text;
        } catch {
          return text || "-";
        }
      },
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
        <Title level={4} style={{ margin: 0 }}>Server Certificates</Title>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            form.resetFields();
            setGenerateModalOpen(true);
          }}
        >
          Generate Server Certificate
        </Button>
      </div>

      <Table
        dataSource={dataSource}
        columns={columns}
        rowKey="id"
        loading={loadingCerts || loadingAuth}
        scroll={{ x: 'max-content' }}
      />

      <Modal
        title="Generate Server Certificate"
        open={generateModalOpen}
        onCancel={() => setGenerateModalOpen(false)}
        footer={null}
      >
        <Form form={form} layout="vertical" onFinish={handleGenerate}>
          <Form.Item
            name="hosts"
            label="Hosts (Domains)"
            rules={[{ required: true, message: "Please input at least one host" }]}
            tooltip="Press enter to add multiple hosts. The first one will be the Common Name (CN), all will be added as SANs."
          >
            <Select mode="tags" style={{ width: '100%' }} placeholder="example.com, api.example.com" />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit">Generate</Button>
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
