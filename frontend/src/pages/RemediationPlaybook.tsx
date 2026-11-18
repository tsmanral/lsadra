import { Navigate, useParams } from 'react-router-dom';

// The playbook for an incident lives on the Response page, which loads it from
// the incident itself. This route stays so older links keep working.
const RemediationPlaybook = () => {
  const { id } = useParams<{ id: string }>();
  return <Navigate to={id ? `/app/response?incident=${encodeURIComponent(id)}` : '/app/response'} replace />;
};

export default RemediationPlaybook;
