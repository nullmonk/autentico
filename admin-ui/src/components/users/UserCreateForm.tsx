import { useState } from "react";
import { Drawer, Form, Input, Select, Button, Space, App, Checkbox } from "antd";
import { useQuery } from "@tanstack/react-query";
import { useCreateUser } from "../../hooks/useUsers";
import { listAuthorities, generateUserCert } from "../../api/ca";

interface UserCreateFormProps {
  open: boolean;
  onClose: () => void;
}

const ROLE_OPTIONS = [
  { label: "User", value: "user" },
  { label: "Admin", value: "admin" },
];

export default function UserCreateForm({
  open,
  onClose,
}: UserCreateFormProps) {
  const { message } = App.useApp();
  const [form] = Form.useForm();
  const createUser = useCreateUser();
  const [generateCert, setGenerateCert] = useState(false);

  const { data: authorities } = useQuery({
    queryKey: ["ca-authorities"],
    queryFn: listAuthorities,
  });

  const activeIntermediary = authorities?.items.find((c) => c.type === "intermediary" && !c.revoked_at);

  const handleSubmit = async (values: any) => {
    try {
      await createUser.mutateAsync({
        username: values.username,
        password: values.password,
        email: values.email,
        role: values.role,
      });

      if (generateCert && activeIntermediary && values.interPassword) {
        try {
          await generateUserCert(values.username, activeIntermediary.id, values.interPassword);
          message.success("User and certificate created successfully");
        } catch (certErr: any) {
          const msg = certErr.response?.data?.error?.error_description || "Failed to generate certificate";
          message.error(`User created, but certificate generation failed: ${msg}`);
        }
      } else {
        message.success("User created successfully");
      }

      form.resetFields();
      setGenerateCert(false);
      onClose();
    } catch {
      message.error("Failed to create user");
    }
  };

  return (
    <Drawer
      title="Create User"
      open={open}
      onClose={onClose}
      width={480}
      extra={
        <Space>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="primary"
            onClick={() => form.submit()}
            loading={createUser.isPending}
          >
            Create
          </Button>
        </Space>
      }
    >
      <Form
        form={form}
        layout="vertical"
        onFinish={handleSubmit}
        initialValues={{ role: "user" }}
      >
        <Form.Item
          name="username"
          label="Username"
          rules={[{ required: true, message: "Username is required" }]}
        >
          <Input />
        </Form.Item>

        <Form.Item
          name="password"
          label="Password"
          rules={[
            { required: true, message: "Password is required" },
            { min: 6, message: "Password must be at least 6 characters" },
          ]}
        >
          <Input.Password />
        </Form.Item>

        <Form.Item
          name="email"
          label="Email"
          rules={[{ type: "email", message: "Must be a valid email" }]}
        >
          <Input />
        </Form.Item>

        <Form.Item name="role" label="Role">
          <Select options={ROLE_OPTIONS} />
        </Form.Item>

        {activeIntermediary && (
          <>
            <Form.Item>
              <Checkbox
                checked={generateCert}
                onChange={(e) => setGenerateCert(e.target.checked)}
              >
                Generate User Certificate
              </Checkbox>
            </Form.Item>

            {generateCert && (
              <Form.Item
                name="interPassword"
                label="Intermediary CA Password"
                rules={[{ required: true, message: "Please enter the Intermediary CA password" }]}
              >
                <Input.Password />
              </Form.Item>
            )}
          </>
        )}
      </Form>
    </Drawer>
  );
}
