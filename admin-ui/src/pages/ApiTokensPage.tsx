import { useState, useCallback, useRef } from "react";
import {
  Typography,
  Table,
  Button,
  Tag,
  Space,
  Popconfirm,
  Input,
  DatePicker,
  Alert,
  App,
  Modal,
  Form,
  Select,
} from "antd";
import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { SorterResult } from "antd/es/table/interface";
import type { Dayjs } from "dayjs";
import dayjs from "dayjs";
import {
  useApiTokens,
  useRevokeApiToken,
  useCreateApiToken,
  useAvailableRoutes,
  type ApiToken,
  type CreateApiTokenRequest,
} from "../hooks/useApiTokens";
import type { ListParams } from "../api/users";
import { useTableScrollY } from "../hooks/useTableScrollY";
import { useApplyDefaultPageSize } from "../hooks/useDefaultPageSize";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS } from "../constants/table";
import CopyText from "../components/CopyText";
import { useHiddenColumns } from "../hooks/useHiddenColumns";

function formatDate(date: string | null): string {
  if (!date) return "—";
  return new Date(date).toLocaleString();
}

export default function ApiTokensPage() {
  const { message, modal } = App.useApp();
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const scrollY = useTableScrollY(tableContainerRef);

  const [listParams, setListParams] = useState<ListParams>({
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    sort: "created_at",
    order: "desc",
  });
  const [dateRange, setDateRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const defaultPageSize = useApplyDefaultPageSize((size) =>
    setListParams((prev) => ({ ...prev, limit: size, offset: 0 }))
  );

  const { data, isLoading, error } = useApiTokens(listParams);
  const revoke = useRevokeApiToken();
  const create = useCreateApiToken();
  const { data: availableRoutes } = useAvailableRoutes();

  const [createVisible, setCreateVisible] = useState(false);
  const [form] = Form.useForm();

  const handleRevoke = async (id: string) => {
    try {
      await revoke.mutateAsync(id);
      message.success("API token revoked");
    } catch {
      message.error("Failed to revoke API token");
    }
  };

  const handleCreate = async () => {
    try {
      const values = await form.validateFields();
      const req: CreateApiTokenRequest = {
        name: values.name,
        expires_at: values.expires_at.toISOString(),
        routes: values.routes,
      };

      const res = await create.mutateAsync(req);

      setCreateVisible(false);
      form.resetFields();

      modal.success({
        title: "API Token Created",
        width: 600,
        content: (
          <div>
            <p>Please copy this token now. You will not be able to see it again!</p>
            <div style={{ marginTop: 16 }}>
              <CopyText text={res.token} />
            </div>
          </div>
        ),
      });
    } catch (e) {
      console.error(e);
      // Let standard error handling handle it unless it's a validate field throw
    }
  };

  const handleDateRange = useCallback(
    (dates: [Dayjs | null, Dayjs | null] | null) => {
      setDateRange(dates);
      setListParams((prev) => {
        const next: ListParams = { ...prev, offset: 0 };
        delete next.created_at_from;
        delete next.created_at_to;
        if (dates && dates[0]) {
          next.created_at_from = dates[0].startOf("day").toISOString();
        }
        if (dates && dates[1]) {
          next.created_at_to = dates[1].endOf("day").toISOString();
        }
        return next;
      });
    },
    []
  );

  const handleTableChange = useCallback(
    (
      pagination: TablePaginationConfig,
      _filters: Record<string, unknown>,
      sorter: SorterResult<ApiToken> | SorterResult<ApiToken>[]
    ) => {
      const s = Array.isArray(sorter) ? sorter[0] : sorter;
      setListParams((prev) => ({
        ...prev,
        offset:
          ((pagination.current ?? 1) - 1) *
          (pagination.pageSize ?? defaultPageSize),
        limit: pagination.pageSize ?? defaultPageSize,
        sort: s.field ? String(s.field) : prev.sort,
        order: s.order === "descend" ? "desc" : "asc",
      }));
    },
    [defaultPageSize]
  );

  const rawColumns0: ColumnsType<ApiToken> = [
    {
      title: "Token ID",
      dataIndex: "id",
      key: "id",
      width: 160,
      render: (id: string) => (
        <CopyText text={id}>{id.slice(0, 12) + "..."}</CopyText>
      ),
    },
    {
      title: "Name",
      dataIndex: "name",
      key: "name",
      ellipsis: true,
      render: (name: string) => name || "—",
    },
    {
      title: "Created By",
      dataIndex: "created_by",
      key: "created_by",
      ellipsis: true,
      render: (createdBy: string) => createdBy || "—",
    },
    {
      title: "Status",
      key: "status",
      width: 100,
      render: (_, record) => {
        const isExpired = new Date(record.expires_at) < new Date();
        return (
          <Tag color={isExpired ? "red" : "green"}>
            {isExpired ? "Expired" : "Active"}
          </Tag>
        );
      },
    },
    {
      title: "Expires",
      dataIndex: "expires_at",
      key: "expires_at",
      width: 180,
      render: formatDate,
    },
    {
      title: "Created At",
      dataIndex: "created_at",
      key: "created_at",
      width: 180,
      sorter: true,
      sortOrder:
        listParams.sort === "created_at"
          ? listParams.order === "desc"
            ? "descend"
            : "ascend"
          : undefined,
      render: formatDate,
    },
    {
      title: "Actions",
      key: "actions",
      width: 80,
      render: (_, record) => (
        <Space>
          <Popconfirm
            title="Revoke this API token?"
            onConfirm={() => handleRevoke(record.id)}
            okText="Revoke"
            okButtonProps={{ danger: true }}
          >
            <Button type="text" size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];
  const columns = useHiddenColumns('/api-tokens', rawColumns0);


  if (error) {
    return <Alert type="error" message="Failed to load API tokens" />;
  }

  return (
    <>
      <Space
        style={{
          justifyContent: "space-between",
          width: "100%",
          flexShrink: 0,
        }}
      >
        <Typography.Title level={4} style={{ margin: 0 }}>
          API Tokens
        </Typography.Title>
        <Space>
          <DatePicker.RangePicker
            value={dateRange}
            onChange={(dates) => handleDateRange(dates)}
            allowClear
          />
          {/* <Input.Search
            placeholder="Search name..."
            allowClear
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onSearch={handleSearch}
            style={{ width: 250 }}
          /> */}
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              form.setFieldsValue({
                expires_at: dayjs().add(1, 'year'),
              });
              setCreateVisible(true);
            }}
          >
            Create API Token
          </Button>
        </Space>
      </Space>

      <div
        ref={tableContainerRef}
        style={{ flex: 1, overflow: "hidden", marginTop: 16 }}
      >
        <Table<ApiToken>
          columns={columns}
          dataSource={data?.items ?? []}
          rowKey="id"
          loading={isLoading}
          onChange={handleTableChange}
          scroll={{ x: 'max-content', y: scrollY ? scrollY : undefined }}
          pagination={{
            current:
              Math.floor(
                (listParams.offset ?? 0) /
                  (listParams.limit ?? defaultPageSize)
              ) + 1,
            pageSize: listParams.limit ?? defaultPageSize,
            total: data?.total ?? 0,
            showSizeChanger: true,
            pageSizeOptions: PAGE_SIZE_OPTIONS,
            showTotal: (total) => `${total} tokens`,
          }}
          size="small"
        />
      </div>

      <Modal
        title="Create API Token"
        open={createVisible}
        onOk={handleCreate}
        confirmLoading={create.isPending}
        onCancel={() => setCreateVisible(false)}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label="Name"
            rules={[{ required: true, message: "Please enter a name" }]}
          >
            <Input placeholder="e.g. CI/CD Pipeline" />
          </Form.Item>
          <Form.Item
            name="expires_at"
            label="Expiration Date"
            rules={[{ required: true, message: "Please select an expiration date" }]}
          >
            <DatePicker showTime style={{ width: "100%" }} />
          </Form.Item>
          <Form.Item
            name="routes"
            label="Allowed Routes"
            rules={[{ required: true, message: "Please select at least one route" }]}
          >
            <Select
              mode="tags"
              style={{ width: "100%" }}
              placeholder="e.g. /admin/api/users:GET"
              options={availableRoutes?.map(r => ({
                value: `${r.path}:${r.method}`,
                label: `${r.path} (${r.method})`
              })) || []}
            />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
