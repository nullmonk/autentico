import { App, Button, Card, Col, Form, Input, Modal, Row, Select, Space, Table, Typography } from "antd";
import { PlusOutlined, EditOutlined, DeleteOutlined } from "@ant-design/icons";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import apiClient from "../api/client";

export default function ApplicationsPage() {
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const { message, modal } = App.useApp();

  const { data: apps = [], isLoading: isLoadingApps } = useQuery({
    queryKey: ["applications"],
    queryFn: () => apiClient.get("/admin/api/applications").then((res: any) => res.data.data),
  });

  const { data: groups = [], isLoading: isLoadingGroups } = useQuery({
    queryKey: ["groups"],
    queryFn: () => apiClient.get("/admin/api/groups").then((res: any) => res.data.data.items || []),
  });

  const saveMutation = useMutation({
    mutationFn: (values: any) =>
      editingId
        ? apiClient.put(`/admin/api/applications/${editingId}`, values)
        : apiClient.post("/admin/api/applications", values),
    onSuccess: () => {
      message.success(editingId ? "Application updated" : "Application created");
      setIsModalVisible(false);
      form.resetFields();
      queryClient.invalidateQueries({ queryKey: ["applications"] });
    },
    onError: (err: any) => {
      message.error(err.response?.data?.error_description || "Failed to save application");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.delete(`/admin/api/applications/${id}`),
    onSuccess: () => {
      message.success("Application deleted");
      queryClient.invalidateQueries({ queryKey: ["applications"] });
    },
    onError: (err: any) => {
      message.error(err.response?.data?.error_description || "Failed to delete application");
    },
  });

  const handleEdit = (app: any) => {
    setEditingId(app.id);
    form.setFieldsValue({
      name: app.name,
      url: app.url,
      icon: app.icon,
      groups: app.groups || [],
    });
    setIsModalVisible(true);
  };

  const handleCreate = () => {
    setEditingId(null);
    form.resetFields();
    setIsModalVisible(true);
  };

  const handleDelete = (app: any) => {
    modal.confirm({
      title: "Delete Application",
      content: `Are you sure you want to delete ${app.name}?`,
      okText: "Delete",
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(app.id),
    });
  };

  const columns = [
    {
      title: "Name",
      dataIndex: "name",
      key: "name",
      render: (text: string, record: any) => (
        <Space>
          {record.icon && (
            <img src={record.icon} alt={text} style={{ width: 24, height: 24, objectFit: "contain" }} />
          )}
          {text}
        </Space>
      ),
    },
    {
      title: "URL",
      dataIndex: "url",
      key: "url",
      render: (text: string) => text ? <a href={text} target="_blank" rel="noreferrer">{text}</a> : "-",
    },
    {
      title: "Groups",
      dataIndex: "groups",
      key: "groups",
      render: (g: string[]) => g ? g.length : 0,
    },
    {
      title: "Actions",
      key: "actions",
      render: (_: any, record: any) => (
        <Space>
          <Button type="text" icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          <Button type="text" danger icon={<DeleteOutlined />} onClick={() => handleDelete(record)} />
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="large" style={{ display: "flex" }}>
      <Row justify="space-between" align="middle">
        <Col>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Applications
          </Typography.Title>
        </Col>
        <Col>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
            Create Application
          </Button>
        </Col>
      </Row>

      <Card>
        <Table
          dataSource={apps}
          columns={columns}
          rowKey="id"
          loading={isLoadingApps}
          pagination={{ hideOnSinglePage: true }}
        />
      </Card>

      <Modal
        title={editingId ? "Edit Application" : "Create Application"}
        open={isModalVisible}
        onOk={() => form.submit()}
        onCancel={() => setIsModalVisible(false)}
        confirmLoading={saveMutation.isPending}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Form.Item
            name="name"
            label="Name"
            rules={[{ required: true, message: "Please enter a name" }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="url"
            label="URL"
          >
            <Input placeholder="https://app.example.com" />
          </Form.Item>
          <Form.Item
            name="icon"
            label="Icon URL"
          >
            <Input placeholder="https://example.com/icon.png" />
          </Form.Item>
          <Form.Item
            name="groups"
            label="Groups"
            tooltip="Users must be in at least one of these groups to see this application."
          >
            <Select
              mode="multiple"
              loading={isLoadingGroups}
              options={groups.map((g: any) => ({ label: g.name, value: g.id }))}
              placeholder="Select ADO groups"
            />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
