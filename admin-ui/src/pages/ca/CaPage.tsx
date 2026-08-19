import { useQuery } from "@tanstack/react-query";
import { Button, Space, Typography, Card, Descriptions } from "antd";
import { StopOutlined, LinkOutlined } from "@ant-design/icons";
import { listAuthorities } from "../../api/ca";

const { Title, Text } = Typography;

export default function CaPage() {

  const { data: authorities } = useQuery({
    queryKey: ["ca-authorities"],
    queryFn: listAuthorities,
  });


  const activeIntermediary = authorities?.items.find((c) => c.type === "intermediary" && !c.revoked_at);
  const hasIntermediary = !!activeIntermediary;

  const intermediaryExpiringSoon = activeIntermediary?.expire_date &&
    (new Date(activeIntermediary.expire_date).getTime() - Date.now() < 180 * 24 * 60 * 60 * 1000); // 180 days ~ 6mo


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

    </Space>
  );
}
