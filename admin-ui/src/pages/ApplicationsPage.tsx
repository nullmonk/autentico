import { App, Button, Card, Col, Form, Input, Modal, Row, Select, Space, Table, Typography } from "antd";
import { PlusOutlined, EditOutlined, DeleteOutlined, ArrowUpOutlined, ArrowDownOutlined } from "@ant-design/icons";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import apiClient from "../api/client";

interface ApplicationNode {
  name: string;
  description?: string;
  icon?: string;
  url?: string;
  groups?: string[];
  items?: ApplicationNode[];
}

export default function ApplicationsPage() {
  const [isModalVisible, setIsModalVisible] = useState(false);
  const [editingNode, setEditingNode] = useState<{ node: ApplicationNode, parentIndex: number, index: number } | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const { message, modal } = App.useApp();

  const { data: apps = [], isLoading: isLoadingApps } = useQuery({
    queryKey: ["applications"],
    queryFn: () => apiClient.get("/admin/api/applications").then((res: any) => res.data.data as ApplicationNode[]),
  });

  const { data: groups = [], isLoading: isLoadingGroups } = useQuery({
    queryKey: ["groups"],
    queryFn: () => apiClient.get("/admin/api/groups").then((res: any) => res.data.data.items || []),
  });

  const saveMutation = useMutation({
    mutationFn: (newApps: ApplicationNode[]) => apiClient.put("/admin/api/applications", newApps),
    onSuccess: () => {
      message.success("Applications updated");
      setIsModalVisible(false);
      form.resetFields();
      queryClient.invalidateQueries({ queryKey: ["applications"] });
    },
    onError: (err: any) => {
      message.error(err.response?.data?.error_description || "Failed to save applications");
    },
  });

  const handleEdit = (node: ApplicationNode, parentIndex: number, index: number) => {
    setEditingNode({ node, parentIndex, index });
    const isCategory = !!node.items;
    form.setFieldsValue({
      type: isCategory ? "category" : "app",
      name: node.name,
      description: node.description,
      url: node.url,
      icon: node.icon,
      groups: node.groups || [],
      categoryId: parentIndex === -1 ? "" : parentIndex.toString(),
    });
    setIsModalVisible(true);
  };

  const handleCreate = () => {
    setEditingNode(null);
    form.resetFields();
    form.setFieldsValue({ type: "app", categoryId: "" });
    setIsModalVisible(true);
  };

  const handleDelete = (parentIndex: number, index: number) => {
    modal.confirm({
      title: "Delete Item",
      content: "Are you sure you want to delete this item?",
      okText: "Delete",
      okButtonProps: { danger: true },
      onOk: () => {
        const newApps = JSON.parse(JSON.stringify(apps));
        if (parentIndex === -1) {
          newApps.splice(index, 1);
        } else {
          newApps[parentIndex].items.splice(index, 1);
        }
        saveMutation.mutate(newApps);
      },
    });
  };

  const handleMove = (parentIndex: number, index: number, direction: 'up' | 'down') => {
    const newApps = JSON.parse(JSON.stringify(apps));
    const list = parentIndex === -1 ? newApps : newApps[parentIndex].items;

    if (direction === 'up' && index > 0) {
      [list[index - 1], list[index]] = [list[index], list[index - 1]];
    } else if (direction === 'down' && index < list.length - 1) {
      [list[index + 1], list[index]] = [list[index], list[index + 1]];
    }

    saveMutation.mutate(newApps);
  };

  const onFinish = (values: any) => {
    const newApps = JSON.parse(JSON.stringify(apps));
    const newNode: ApplicationNode = {
      name: values.name || "",
    };

    if (values.type === "app") {
      newNode.description = values.description;
      newNode.url = values.url;
      newNode.icon = values.icon;
      newNode.groups = values.groups;
    } else {
      newNode.items = editingNode && editingNode.node.items ? editingNode.node.items : [];
    }

    if (editingNode) {
      // First, remove it from the old location
      if (editingNode.parentIndex === -1) {
        newApps.splice(editingNode.index, 1);
      } else {
        newApps[editingNode.parentIndex].items.splice(editingNode.index, 1);
      }

      // Then insert it into the new location
      if (values.type === "app" && values.categoryId !== "" && values.categoryId !== undefined) {
        const catIndex = parseInt(values.categoryId, 10);
        if (newApps[catIndex] && newApps[catIndex].items) {
          newApps[catIndex].items.push(newNode);
        } else {
          newApps.push(newNode);
        }
      } else {
        // If it's a category, or an app with no category, add it to root
        // If it was already at root, try to put it back exactly where it was (unless we are reordering)
        if (editingNode.parentIndex === -1 && (values.type === "category" || values.categoryId === "")) {
          newApps.splice(editingNode.index, 0, newNode);
        } else {
          newApps.push(newNode);
        }
      }
    } else {
      if (values.categoryId !== "" && values.categoryId !== undefined) {
        const catIndex = parseInt(values.categoryId, 10);
        if (newApps[catIndex] && newApps[catIndex].items) {
          newApps[catIndex].items.push(newNode);
        } else {
          newApps.push(newNode);
        }
      } else {
        newApps.push(newNode);
      }
    }

    saveMutation.mutate(newApps);
  };

  // Flatten apps for table
  const tableData: any[] = [];
  apps.forEach((app: ApplicationNode, i: number) => {
    tableData.push({ ...app, parentIndex: -1, index: i, key: `root-${i}` });
    if (app.items) {
      app.items.forEach((subApp: ApplicationNode, j: number) => {
        tableData.push({ ...subApp, parentIndex: i, index: j, key: `child-${i}-${j}` });
      });
    }
  });

  const columns = [
    {
      title: "Name",
      dataIndex: "name",
      key: "name",
      render: (text: string, record: any) => (
        <div style={{ paddingLeft: record.parentIndex !== -1 ? 24 : 0 }}>
          <Space>
            {record.icon && (
              <img src={record.icon} alt={text} style={{ width: 24, height: 24, objectFit: "contain" }} />
            )}
            {record.items ? <strong>{text || "(Spacer)"}</strong> : text}
          </Space>
          {record.description && <div style={{ fontSize: '12px', color: '#888' }}>{record.description}</div>}
        </div>
      ),
    },
    {
      title: "Type",
      key: "type",
      render: (_: any, record: any) => record.items ? "Category" : "Application",
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
      render: (_: any, record: any) => {
        const listLength = record.parentIndex === -1 ? apps.length : (apps[record.parentIndex]?.items?.length || 0);
        const canMoveUp = record.index > 0;
        const canMoveDown = record.index < listLength - 1;

        return (
          <Space>
            <Button type="text" icon={<ArrowUpOutlined />} disabled={!canMoveUp} onClick={() => handleMove(record.parentIndex, record.index, 'up')} />
            <Button type="text" icon={<ArrowDownOutlined />} disabled={!canMoveDown} onClick={() => handleMove(record.parentIndex, record.index, 'down')} />
            <Button type="text" icon={<EditOutlined />} onClick={() => handleEdit(record, record.parentIndex, record.index)} />
            <Button type="text" danger icon={<DeleteOutlined />} onClick={() => handleDelete(record.parentIndex, record.index)} />
          </Space>
        );
      },
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
            Add Item
          </Button>
        </Col>
      </Row>

      <Card>
        <Table
          dataSource={tableData}
          columns={columns}
          rowKey="key"
          loading={isLoadingApps}
          pagination={false}
        />
      </Card>

      <Modal
        title={editingNode ? "Edit Item" : "Add Item"}
        open={isModalVisible}
        onOk={() => form.submit()}
        onCancel={() => setIsModalVisible(false)}
        confirmLoading={saveMutation.isPending}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={onFinish}
        >
          <Form.Item name="type" label="Type" rules={[{ required: true }]}>
            <Select disabled={!!editingNode}>
              <Select.Option value="app">Application</Select.Option>
              <Select.Option value="category">Category</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item
            noStyle
            shouldUpdate={(prevValues, currentValues) => prevValues.type !== currentValues.type}
          >
            {({ getFieldValue }) => (
              <>
                <Form.Item
                  name="name"
                  label="Name"
                  rules={[{ required: getFieldValue("type") === "app", message: "Please enter a name" }]}
                  tooltip={getFieldValue("type") === "category" ? "Leave empty for a spacer." : ""}
                >
                  <Input />
                </Form.Item>

                {getFieldValue("type") === "app" && (
                  <>
                    <Form.Item name="description" label="Description">
                      <Input />
                    </Form.Item>
                    <Form.Item name="url" label="URL">
                      <Input placeholder="https://app.example.com" />
                    </Form.Item>
                    <Form.Item name="icon" label="Icon URL">
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

                    {/* Add Category Selection here so apps can be put in categories or moved. */}
                    {(
                       <Form.Item name="categoryId" label="Category">
                          <Select placeholder="Root (No Category)">
                             <Select.Option value="">None</Select.Option>
                             {apps.map((app: any, idx: number) => {
                               if (app.items) {
                                 return <Select.Option key={idx} value={idx}>{app.name || "(Spacer)"}</Select.Option>
                               }
                               return null;
                             })}
                          </Select>
                       </Form.Item>
                    )}
                  </>
                )}
              </>
            )}
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
