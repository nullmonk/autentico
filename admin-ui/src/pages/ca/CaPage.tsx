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


  const legacyIntermediary = authorities?.items.find((c) => c.type === "intermediary" && !c.revoked_at);
  const clientIntermediary = authorities?.items.find((c) => c.type === "client-int" && !c.revoked_at) || legacyIntermediary;
  const serverIntermediary = authorities?.items.find((c) => c.type === "server-int" && !c.revoked_at);

  const hasIntermediary = !!clientIntermediary || !!serverIntermediary;

  const isExpiringSoon = (cert: any) =>
    cert?.expire_date && (new Date(cert.expire_date).getTime() - Date.now() < 365 * 24 * 60 * 60 * 1000); // 1 year warning

  const clientExpiringSoon = isExpiringSoon(clientIntermediary);
  const serverExpiringSoon = isExpiringSoon(serverIntermediary);


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

      {(clientExpiringSoon || serverExpiringSoon) && (
        <Card style={{ borderColor: "#faad14", backgroundColor: "#fffbe6" }}>
          <Text type="warning">
            <StopOutlined /> One or more intermediary CAs have less than 1 year remaining.
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
          {clientIntermediary && (
            <>
              <Descriptions.Item label="Client Intermediary CA ID"><Text copyable>{clientIntermediary.id}</Text></Descriptions.Item>
              <Descriptions.Item label="Client Intermediary CA Expiration">{clientIntermediary.expire_date ? new Date(clientIntermediary.expire_date).toLocaleString() : "-"}</Descriptions.Item>
            </>
          )}
          {serverIntermediary && (
            <>
              <Descriptions.Item label="Server Intermediary CA ID"><Text copyable>{serverIntermediary.id}</Text></Descriptions.Item>
              <Descriptions.Item label="Server Intermediary CA Expiration">{serverIntermediary.expire_date ? new Date(serverIntermediary.expire_date).toLocaleString() : "-"}</Descriptions.Item>
            </>
          )}
        </Descriptions>
      </Card>

    </Space>
  );
}
