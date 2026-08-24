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
      categoryId: parentIndex === -1 ? [] : [parentIndex.toString()],
    });
    setIsModalVisible(true);
  };

  const handleCreate = () => {
    setEditingNode(null);
    form.resetFields();
    form.setFieldsValue({ type: "app", categoryId: [] });
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

    if (direction === 'up') {
      if (parentIndex !== -1) {
        if (index === 0) {
          const item = newApps[parentIndex].items.splice(index, 1)[0];
          newApps.splice(parentIndex, 0, item);
        } else {
          const list = newApps[parentIndex].items;
          [list[index - 1], list[index]] = [list[index], list[index - 1]];
        }
      } else {
        if (index > 0) {
          const isCategory = !!newApps[index].items;
          const isAboveCategory = !!newApps[index - 1].items;

          if (!isCategory && isAboveCategory) {
            const item = newApps.splice(index, 1)[0];
            newApps[index - 1].items.push(item);
          } else {
            [newApps[index - 1], newApps[index]] = [newApps[index], newApps[index - 1]];
          }
        }
      }
    } else if (direction === 'down') {
      if (parentIndex !== -1) {
        const list = newApps[parentIndex].items;
        if (index === list.length - 1) {
          const item = list.splice(index, 1)[0];
          newApps.splice(parentIndex + 1, 0, item);
        } else {
          [list[index + 1], list[index]] = [list[index], list[index + 1]];
        }
      } else {
        if (index < newApps.length - 1) {
          const isCategory = !!newApps[index].items;
          const isBelowCategory = !!newApps[index + 1].items;

          if (!isCategory && isBelowCategory) {
            const item = newApps.splice(index, 1)[0];
            newApps[index].items.unshift(item);
          } else {
            [newApps[index + 1], newApps[index]] = [newApps[index], newApps[index + 1]];
          }
        }
      }
    }

    saveMutation.mutate(newApps);
  };

  const onFinish = (values: any) => {
    const newApps = JSON.parse(JSON.stringify(apps));
    const newNode: ApplicationNode = {
      name: values.name || "",
    };

    let selectedCatValue = "";
    if (values.categoryId && values.categoryId.length > 0) {
      selectedCatValue = values.categoryId[values.categoryId.length - 1]; // get the last selected/typed tag
    }

    // Identify if typed tag matches an existing category
    if (selectedCatValue !== "" && isNaN(parseInt(selectedCatValue, 10))) {
      const existingIdx = newApps.findIndex((a: any) => a.items && a.name.toLowerCase() === selectedCatValue.toLowerCase());
      if (existingIdx !== -1) {
        selectedCatValue = existingIdx.toString();
      }
    }

    if (values.type === "app") {
      newNode.description = values.description;
      newNode.url = values.url;
      newNode.icon = values.icon;
      newNode.groups = values.groups;
    } else {
      newNode.items = editingNode && editingNode.node.items ? editingNode.node.items : [];
    }

    let targetCategory: ApplicationNode | null = null;
    let createNewCategoryName: string | null = null;

    if (selectedCatValue !== "") {
      if (!isNaN(parseInt(selectedCatValue, 10))) {
        targetCategory = newApps[parseInt(selectedCatValue, 10)];
      } else {
        createNewCategoryName = selectedCatValue;
      }
    }

    if (editingNode) {
      // First, remove it from the old location
      if (editingNode.parentIndex === -1) {
        newApps.splice(editingNode.index, 1);
      } else {
        newApps[editingNode.parentIndex].items.splice(editingNode.index, 1);
      }
    }

    if (values.type === "app") {
      if (targetCategory) {
        if (!targetCategory.items) targetCategory.items = [];
        targetCategory.items.push(newNode);
      } else if (createNewCategoryName) {
        newApps.push({
          name: createNewCategoryName,
          items: [newNode]
        });
      } else {
        if (editingNode && editingNode.parentIndex === -1) {
          // Put back in its original root slot, adjusted for removal
          newApps.splice(editingNode.index, 0, newNode);
        } else {
          newApps.push(newNode);
        }
      }
    } else {
      if (editingNode && editingNode.parentIndex === -1) {
        // Put back in its original root slot
        newApps.splice(editingNode.index, 0, newNode);
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
        let canMoveUp = false;
        let canMoveDown = false;

        if (record.parentIndex !== -1) {
          canMoveUp = true; // Can always move up (reorder or escape)
          canMoveDown = true; // Can always move down (reorder or escape)
        } else {
          canMoveUp = record.index > 0;
          canMoveDown = record.index < apps.length - 1;
        }

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
            Create Application
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
        title={editingNode ? (form.getFieldValue("type") === "category" ? "Edit Category" : "Edit Application") : "Create Application"}
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
          {/* Hide the type selector since users only create apps now (categories created dynamically) */}
          <Form.Item name="type" hidden>
            <Input />
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
                          <Select mode="tags" maxCount={1} placeholder="Select or type a new category (Empty = Root)">
                             {apps.map((app: any, idx: number) => {
                               if (app.items) {
                                 return <Select.Option key={idx} value={idx.toString()}>{app.name || "(Spacer)"}</Select.Option>
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
