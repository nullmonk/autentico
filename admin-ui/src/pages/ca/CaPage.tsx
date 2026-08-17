import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Table, Button, Space, Typography, Tag, Modal, Input, Form, message, Card } from "antd";
import { DownloadOutlined, StopOutlined, PlusOutlined } from "@ant-design/icons";
import { listCertificates, listAuthorities, revokeCertificate, generateUserCert, downloadUserCert } from "../../api/ca";
import { Certificate } from "../../types/ca";

const { Title, Text } = Typography;

export default function CaPage() {
  const queryClient = useQueryClient();
  const [downloadModalOpen, setDownloadModalOpen] = useState(false);
  const [generateModalOpen, setGenerateModalOpen] = useState(false);
  const [selectedCertId, setSelectedCertId] = useState<string | null>(null);
  const [form] = Form.useForm();

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

  const hasIntermediary = authorities?.items.some((c) => c.type === "intermediary" && !c.revoked_at);

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

      const blob = await generateUserCert(values.userId, activeIntermediary.id, values.interPassword, values.bundlePassword);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `bundle.p12`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setGenerateModalOpen(false);
      form.resetFields();
      queryClient.invalidateQueries({ queryKey: ["ca-certificates"] });
      message.success("Certificate generated and downloaded");
    } catch (err) {
      message.error("Failed to generate certificate bundle");
    }
  };

  const columns = [
    {
      title: "ID",
      dataIndex: "id",
      key: "id",
      render: (text: string) => <Text copyable>{text}</Text>,
    },
    {
      title: "User",
      dataIndex: "username",
      key: "username",
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
      render: (_: any, record: Certificate) => (
        record.revoked_at ? <Tag color="red">Revoked</Tag> : <Tag color="green">Active</Tag>
      ),
    },
    {
      title: "Actions",
      key: "actions",
      render: (_: any, record: Certificate) => (
        <Space>
          <Button
            type="text"
            icon={<DownloadOutlined />}
            disabled={!!record.revoked_at}
            onClick={() => {
              setSelectedCertId(record.id);
              setDownloadModalOpen(true);
            }}
          >
            Download
          </Button>
          <Button
            type="text"
            danger
            icon={<StopOutlined />}
            disabled={!!record.revoked_at}
            onClick={() => {
              Modal.confirm({
                title: "Revoke Certificate?",
                content: "Are you sure you want to revoke this certificate? This action cannot be undone.",
                onOk: () => revokeMutation.mutate(record.id),
              });
            }}
          >
            Revoke
          </Button>
        </Space>
      ),
    },
  ];

  if (!hasIntermediary) {
    return (
      <Card>
        <Title level={4}>Certificate Authority</Title>
        <Text type="warning">Enable CA via CLI: run `autentico ca init` followed by `autentico ca inter` to set up the Root and Intermediary CAs.</Text>
      </Card>
    );
  }

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Title level={4} style={{ margin: 0 }}>Certificates</Title>
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
        dataSource={certs?.items || []}
        columns={columns}
        rowKey="id"
        loading={loadingCerts || loadingAuth}
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
            name="userId"
            label="User ID"
            rules={[{ required: true, message: "Please enter the User ID" }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="interPassword"
            label="Intermediary CA Password"
            rules={[{ required: true, message: "Please enter the Intermediary CA password" }]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item
            name="bundlePassword"
            label="New Bundle Password"
            rules={[{ required: true, message: "Please enter a password for the new bundle" }]}
          >
            <Input.Password />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit">Generate & Download</Button>
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
