import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Table, Button, Space, Typography, Tag, Modal, Input, Form, message, Card, AutoComplete, Descriptions } from "antd";
import { DownloadOutlined, StopOutlined, PlusOutlined, LinkOutlined } from "@ant-design/icons";
import { listCertificates, listAuthorities, revokeCertificate, generateUserCert, downloadUserCert } from "../../api/ca";
import { Certificate } from "../../types/ca";
import { listUsers } from "../../api/users";

const { Title, Text } = Typography;

export default function CaPage() {
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

  const activeIntermediary = authorities?.items.find((c) => c.type === "intermediary" && !c.revoked_at);
  const hasIntermediary = !!activeIntermediary;

  const intermediaryExpiringSoon = activeIntermediary?.expire_date &&
    (new Date(activeIntermediary.expire_date).getTime() - Date.now() < 180 * 24 * 60 * 60 * 1000); // 180 days ~ 6mo

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
        <Text type="warning">Enable CA via CLI: run `autentico ca init` to set up the Root and Intermediary CAs.</Text>
      </Card>
    );
  }

  const rootCa = authorities?.items.find(c => c.type === "ca" && !c.revoked_at);

  return (
    <Space direction="vertical" style={{ width: "100%" }} size="large">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Title level={4} style={{ margin: 0 }}>Certificate Authority (CA)</Title>
        <Button
          icon={<LinkOutlined />}
          href="/ca.crt"
        >
          Download CA Chain
        </Button>
      </div>

      {intermediaryExpiringSoon && (
        <Card style={{ borderColor: "#faad14", backgroundColor: "#fffbe6" }}>
          <Text type="warning">
            <StopOutlined /> The intermediary CA is expiring soon.
            Run `autentico ca refresh` in the CLI to generate a new intermediary CA.
          </Text>
        </Card>
      )}

      <Card>
        <Descriptions column={{ xxl: 2, xl: 2, lg: 2, md: 1, sm: 1, xs: 1 }}>
          {rootCa && (
            <>
              <Descriptions.Item label="Root CA ID"><Text copyable>{rootCa.id}</Text></Descriptions.Item>
              <Descriptions.Item label="Root CA Expiration">{rootCa.expire_date ? new Date(rootCa.expire_date).toLocaleString() : "-"}</Descriptions.Item>
            </>
          )}
          {activeIntermediary && (
            <>
              <Descriptions.Item label="Intermediary CA ID"><Text copyable>{activeIntermediary.id}</Text></Descriptions.Item>
              <Descriptions.Item label="Intermediary CA Expiration">{activeIntermediary.expire_date ? new Date(activeIntermediary.expire_date).toLocaleString() : "-"}</Descriptions.Item>
            </>
          )}
        </Descriptions>
      </Card>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 24 }}>
        <Title level={4} style={{ margin: 0 }}>Issued User Certificates</Title>
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
        dataSource={(certs?.items || []).filter(c => c.type === "user")}
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
